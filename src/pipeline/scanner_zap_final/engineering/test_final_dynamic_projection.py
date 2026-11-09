"""Independent response evidence and typed endpoint regression tests."""
import base64
import copy
import hashlib
import json
import unittest
from study.final_output_adapter import fixture_identity
from study.final_dynamic_projection import http_projection, authorization_projection, rag_reference_observations


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = {'route_aliases': {}}
        self.obs = {'finding_id':'fresh', 'coordinate': {'status':'localized','method':'GET','path':'/api/products/',
                    'actor':'absent','response_status':200}, 'native_content':{'native_rule':'10021'}}
        self.refs = [{'case_id':'ref','population':'aigoat-http-properties','truth':'positive',
                      'details':{'coordinate':{'resource':'GET /api/products/','context':'absent',
                                               'property':'missing_header:x-content-type-options'}}}]
        self.trace = [{'phase':phase,'forwarded':True,'method':'GET','path':'/api/products/',
                       'auth_role':'absent','status':200,'response_headers':[],'sequence':1,'response_sha256':'a'*64}
                      for phase in ('before','after')]

    def test_http_property_does_not_assign_security_tp(self):
        result = http_projection(self.obs,self.refs,self.trace,self.fixture)
        self.assertEqual(result['status'],'verified_property')
        self.assertEqual(result['native_label'],'unresolved')

    def test_changed_after_headers_withhold_score(self):
        self.trace[1]['response_headers']=[['X-Content-Type-Options','nosniff']]
        self.assertEqual(http_projection(self.obs,self.refs,self.trace,self.fixture)['status'],'reference_drift')

    def test_scanner_trace_cannot_substitute_independent_reference(self):
        for r in self.trace:r['phase']='scanner'
        self.assertEqual(http_projection(self.obs,self.refs,self.trace,self.fixture)['status'],'reference_unavailable')

    def test_wrong_reference_role_does_not_match(self):
        self.refs[0]['details']['coordinate']['context']='alice'
        self.assertEqual(http_projection(self.obs,self.refs,self.trace,self.fixture)['status'],'outside_frozen_reference')

    def test_bucket_flag_alone_is_not_disclosure(self):
        obs={'finding_id':'bucket','coordinate':{'path':'/identity/api/v2/vehicle/{owner:a}/location'},
             'native_content':{'checker':'NameSpaceRuleChecker','reported_method':'GET','native_reproducible':True}}
        private={'a':{'email':'a@lab','vehicles':[{'uuid':'aa'}]},'b':{'email':'b@lab','vehicles':[{'uuid':'bb'}]}}
        fixture=fixture_identity('crapi',private)
        self.assertEqual(authorization_projection(obs,{'a':'ra','b':'rb'},[],fixture,private)['status'],
                         'no_independent_disclosure_witness')
        body=json.dumps({'carId':'aa','email':'a@lab','vehicleLocation':{'latitude':1,'longitude':2}}).encode()
        trace=[{'phase':'scanner','forwarded':True,'method':'GET','path':'/identity/api/v2/vehicle/aa/location',
                'auth_role':'b','status':200,'sequence':1,'response_body_base64':base64.b64encode(body).decode(),
                'response_sha256':hashlib.sha256(body).hexdigest()}]
        obs['native_content']['native_reproducible']=False
        self.assertEqual(authorization_projection(obs,{'a':'ra','b':'rb'},trace,fixture,private)['status'],'verified_object_disclosure')
        trace[0]['auth_role']='a'
        self.assertEqual(authorization_projection(obs,{'a':'ra','b':'rb'},trace,fixture,private)['status'],
                         'no_independent_disclosure_witness')

    def test_own_document_inclusion_remains_negative_control(self):
        refs=[{'case_id':'r','population':'aigoat-rag-context-authorization','truth':'negative',
               'source_reference_id':'aigoat:llm02-4:alice-document-alice-L0'}]
        phase={'controls':[{'id':'alice-document-alice-L0','actor':'alice','passed':True,
                            'context_signature':[[1,True,None]]}]}
        result=rag_reference_observations(refs,phase,phase)[0]
        self.assertFalse(result['unauthorized_inclusion'])
        self.assertIsNone(result['scanner_coverage'])

    def test_string_context_flag_is_not_a_boolean_observation(self):
        refs=[{'case_id':'r','population':'aigoat-rag-context-authorization','truth':'positive',
               'source_reference_id':'aigoat:llm02-4:alice-document-bob-L0'}]
        phase={'controls':[{'id':'alice-document-bob-L0','actor':'bob','passed':True,
                            'context_signature':[[1,'false',None]]}]}
        self.assertEqual(rag_reference_observations(refs,phase,phase)[0]['status'],'reference_drift')

    def test_changed_actor_is_not_an_equivalent_reference(self):
        refs=[{'case_id':'r','population':'aigoat-rag-context-authorization','truth':'positive',
               'source_reference_id':'aigoat:llm02-4:alice-document-bob-L0'}]
        phase={'controls':[{'id':'alice-document-bob-L0','actor':'bob','passed':True,
                            'context_signature':[[1,True,None]]}]}
        after=copy.deepcopy(phase); after['controls'][0]['actor']='alice'
        self.assertEqual(rag_reference_observations(refs,phase,after)[0]['status'],'reference_drift')


if __name__ == '__main__': unittest.main()
