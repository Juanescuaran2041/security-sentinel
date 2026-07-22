from security_pr_guardian.core.models import LogEvent

class StructuredLogger:

    def __init__ (self, analysis_id:str):
        self.analysis_id = analysis_id

    def log(self, component:str, event:str, details:dict, duration_ms:int| None = None):
        logEvent = LogEvent(analysis_id = self.analysis_id, 
        component = component, event= event, details = details, duration_ms = duration_ms )

        #convertir a json
        json_string = logEvent.model_dump_json()
        print(json_string) 





