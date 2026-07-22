from abc import ABC, abstractmethod

from security_pr_guardian.core.models import StaticAnalysisResult

class StaticAnalysisPort(ABC):
    def __init__(self, file_path):
        self.file_path = file_path

    @abstractmethod
    async def analyze_diff (self, diff:str) -> StaticAnalysisResult:
        raise NotImplemented

    


