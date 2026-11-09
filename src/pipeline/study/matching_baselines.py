"""Explicit published-method adaptations; keys never establish vulnerability truth.

Method attribution and deviations: MATCHING_COMPARATOR_CONTRACT.md.
Java parsing dependencies are installed separately and imported only when used.
"""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import PurePosixPath
import re


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class JavaScopes:
    """Java-specific scope/offset adaptation, not the GitLab generic parser."""
    kinds={'class_declaration','interface_declaration','enum_declaration',
           'record_declaration','annotation_type_declaration','method_declaration',
           'constructor_declaration','compact_constructor_declaration'}
    comments={'line_comment','block_comment'}
    literals={'string_literal','character_literal','text_block'}

    def __init__(self, source, relative_path):
        from tree_sitter import Language, Parser
        import tree_sitter_java
        path=PurePosixPath(relative_path)
        if path.is_absolute() or '..' in path.parts:raise ValueError('Source path must be canonical and relative')
        self.source=source;self.path=path.as_posix()
        self.tree=Parser(Language(tree_sitter_java.language())).parse(source)
        self.valid=not self.tree.root_node.has_error
        self.scopes=[];self.functional=set();self.unsupported=[];ordinals=Counter()
        def end_line(node):
            return node.end_point.row+1-(node.end_point.column==0 and node.end_point.row>node.start_point.row)
        self.end_line=end_line
        root={'tag':[self.path],'start':1,'end':max(1,len(source.splitlines())),'kind':'file'}
        self.scopes.append(root)
        def walk(node, parent):
            if node.type in self.comments:return
            current=parent
            if node.type=='lambda_expression' or (node.type=='class_body' and node.parent.type=='object_creation_expression'):
                self.unsupported.append((node.start_point.row+1,end_line(node),node.type))
            if node.type in self.kinds:
                name=node.child_by_field_name('name')
                if name is None:
                    self.unsupported.append((node.start_point.row+1,end_line(node),'unnamed_scope'))
                else:
                    text=source[name.start_byte:name.end_byte].decode('utf-8')
                    key=(tuple(parent['tag']),text);index=ordinals[key];ordinals[key]+=1
                    current={'tag':parent['tag']+[text+'['+str(index)+']'],
                        'start':node.start_point.row+1,'end':end_line(node),'kind':node.type}
                    self.scopes.append(current)
            if node.type in self.literals:
                self.functional.update(range(node.start_point.row+1,end_line(node)+1));return
            if not node.children:
                if source[node.start_byte:node.end_byte].strip():
                    self.functional.update(range(node.start_point.row+1,end_line(node)+1))
            for child in node.children:walk(child,current)
        walk(self.tree.root_node,root)

    def locate(self, line):
        if not self.valid:return {'status':'parse_error'}
        if isinstance(line,bool) or not isinstance(line,int) or line<1 or line>self.scopes[0]['end']:
            return {'status':'invalid_location'}
        if any(a<=line<=b for a,b,_ in self.unsupported):return {'status':'unsupported_scope'}
        if line not in self.functional:return {'status':'nonfunctional_location'}
        candidates=[s for s in self.scopes if s['start']<=line<=s['end']]
        score=min((s['end']-s['start'],-len(s['tag'])) for s in candidates)
        best=[s for s in candidates if (s['end']-s['start'],-len(s['tag']))==score]
        if len(best)!=1:return {'status':'ambiguous_scope'}
        scope=best[0];offset=line-scope['start']
        nfl=sum(i not in self.functional for i in range(scope['start'],line))
        return {'status':'supported','scope':scope,'line':line,'offset':offset,
                'nonfunctional_lines_before_location':nfl,'normalized_offset':offset-nfl}


def sast_key(parsed, line, cwes, partition, method):
    if method not in {'line','scope_offset','normalized_scope_offset'}:raise ValueError('Unknown SAST method')
    classes=sorted(set(cwes))
    if len(classes)!=1 or not re.fullmatch(r'CWE-[1-9][0-9]*',classes[0]):
        return {'status':'insufficient_or_multiple_weakness_classes','key':None}
    located=parsed.locate(line)
    if located['status']!='supported':return {**located,'key':None}
    # The common partition is fixed by the caller for every comparator.
    if not partition:raise ValueError('An explicit population partition is required')
    if method=='line':identity=[partition,parsed.path,line,classes[0]]
    else:identity=[partition,located['scope']['tag'],located['normalized_offset' if method=='normalized_scope_offset' else 'offset'],classes[0]]
    return {**located,'method':method,'identity':identity,'key':fingerprint(identity)}


def group_keys(rows):
    """Keep exact membership and unsupported records; no union through wildcards."""
    groups=defaultdict(list);unresolved=[];ids=set()
    for row in rows:
        fid=row['finding_id']
        if fid in ids:raise ValueError('Duplicate finding ID')
        ids.add(fid)
        if row.get('status')!='supported' or row.get('key') is None:unresolved.append(fid)
        else:groups[row['key']].append(fid)
    return {'groups':[{'key':k,'members':sorted(v)} for k,v in sorted(groups.items())],
            'unresolved_finding_ids':sorted(unresolved)}


def request_identity(record, aliases, weakness_required=True):
    """Conservative DASTestBed-inspired identity with explicit common partitions.

    Path escapes/slashes and query/body-name case are preserved. Only explicit
    host aliases are allowed. Absence of status is distinct from an empty value.
    """
    if not record.get('partition'):return None,'missing_partition'
    target=aliases.get(record.get('target'))
    if not target:return None,'unknown_target_alias'
    method=record.get('method');path=record.get('path');surface=record.get('surface')
    if not isinstance(method,str) or not method.strip() or not isinstance(path,str) or not path.startswith('/'):
        return None,'missing_request_identity'
    if not isinstance(surface,str) or not surface.strip():return None,'missing_surface'
    surface=surface.lower();name=record.get('name')
    if surface in {'header','cookie','query','body','param'} and (not isinstance(name,str) or not name):
        return None,'missing_surface_name'
    if surface=='header' and isinstance(name,str):name=name.lower()
    weak=record.get('weakness')
    if weakness_required and (not isinstance(weak,dict) or not isinstance(weak.get('class'),str) or not weak['class'] or not isinstance(weak.get('variant'),dict)):
        return None,'missing_weakness_identity'
    request_path=path.split('?',1)[0].split('#',1)[0]
    key=[record['partition'],target,method.upper(),request_path,surface,name]
    if weakness_required:key.append(weak)
    return canonical(key),None


def match_requests(references, findings, aliases, mode='v2'):
    """Explicit v2 subset or separately named legacy request-only comparator.

    Unmatched is not false positive. Missing status permits the status-less
    reference key; a supplied status must be in the declared allowed set.
    """
    if mode not in {'v2','legacy'}:raise ValueError('Unknown DAST method')
    refs={};index=defaultdict(list)
    for row in references:
        ident=row['case_id']
        if ident in refs:raise ValueError('Duplicate case ID')
        key,error=request_identity(row,aliases,mode=='v2')
        if error:raise ValueError('Incomplete reference: '+error)
        statuses=row.get('allowed_statuses')
        if not isinstance(statuses,list) or not statuses or any(type(s)!=int or s<100 or s>599 for s in statuses):
            raise ValueError('Explicit reference statuses required')
        refs[ident]=row;index[key].append(ident)
    result=[];seen=set()
    for row in findings:
        fid=row['finding_id']
        if fid in seen:raise ValueError('Duplicate finding ID')
        seen.add(fid);key,error=request_identity(row,aliases,mode=='v2');status=row.get('status_code')
        if status is not None and (type(status)!=int or status<100 or status>599):error='invalid_status'
        candidates=[] if error else sorted(c for c in index.get(key,[]) if status is None or status in refs[c]['allowed_statuses'])
        state='insufficient_identity' if error else 'unmatched' if not candidates else 'matched' if len(candidates)==1 else 'ambiguous'
        result.append({'finding_id':fid,'method':'dastestbed_'+mode+'_adapted','status':state,'reason':error,
            'candidate_case_ids':candidates,'case_id':candidates[0] if state=='matched' else None})
    return result


def score_pairs(relations, predicted_keys):
    """Pair-level identity errors against external judgments, never CWE labels.

    Unknown relations and unsupported predictions cannot disappear from totals.
    The caller must justify pair sampling; this is not a prevalence estimator.
    """
    counts=Counter();seen=set();details=[]
    for relation in relations:
        a,b=relation['left'],relation['right'];pair=frozenset((a,b))
        if len(pair)!=2 or pair in seen:raise ValueError('Invalid or duplicate pair')
        seen.add(pair)
        if a not in predicted_keys or b not in predicted_keys:raise ValueError('Missing finding prediction')
        if not relation.get('evidence_ids'):raise ValueError('Independent evidence required')
        truth=relation['relation']
        if truth not in {'same','different','unknown'}:raise ValueError('Unknown relation label')
        ka,kb=predicted_keys[a],predicted_keys[b]
        if truth=='unknown':outcome='unresolved_reference'
        elif ka is None or kb is None:outcome='unsupported_prediction'
        elif ka==kb:outcome='correct_merge' if truth=='same' else 'false_merge'
        else:outcome='false_split' if truth=='same' else 'correct_separation'
        counts[outcome]+=1;details.append({'left':a,'right':b,'outcome':outcome})
    return {'counts':dict(sorted(counts.items())),'pairs':details,'unit':'explicitly evidenced finding pair'}
