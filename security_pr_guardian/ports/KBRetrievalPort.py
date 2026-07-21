from abc import ABC, abstractmethod

from security_pr_guardian.core.models import KBFragment, CandidateFinding

class KBRetrievalPort(ABC):

    @abstractmethod
    def retrieve(self, findings: CandidateFinding) -> list[KBFragment]:
        raise NotImplementedError



        