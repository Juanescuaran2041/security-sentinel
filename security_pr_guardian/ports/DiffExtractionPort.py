from abc import ABC, abstractmethod

from security_pr_guardian.core.models import DependencyChange

def DiffExtractionPort(ABC):

    @abstractmethod
    async def get_diff(self, repo:str, pr_number:int) -> str:
        raise NotImplementedError

    @abstractmethod    
    async def get_dependency_changes(self, diff:str) -> list[DependencyChange]:
        raise NotImplementedError

        