class LLMEValidationError(Exception):
    def __init__(self, finding_id: str, reason:str):
        self.finding_id = finding_id
        self.reason = reason
        super().__init__(f"No se pudo evaluar el finding {finding_id}: {reason}")
