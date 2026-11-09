"""Unchanged conservative completion classifier."""

def classify_completion(response, packet, validator):
    """Transport/format failures retain; never salvage truncated output."""
    try:
        choices=response['choices']
        if len(choices)!=1:raise ValueError('Unexpected choice count')
        choice=choices[0];message=choice['message']
        if choice['finish_reason']!='stop':raise ValueError('Incomplete completion')
        if message.get('tool_calls') or message.get('function_call'):raise ValueError('Unexpected tool call')
        if message.get('reasoning_content'):raise ValueError('Unexpected reasoning output')
        content=message['content']
        if not isinstance(content,str):raise ValueError('Missing text content')
        return validator(content,packet)
    except (ValueError,KeyError,TypeError,IndexError) as error:
        return {'finding_id':packet['finding_id'],'status':'invalid_completion','action':'retain',
                'effective_action':'retain','error':type(error).__name__+': '+str(error)}
