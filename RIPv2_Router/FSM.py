"""
   Router finite state machine
"""


class RouterFSM:

    def __init__(self, rip_router):
        self.router = rip_router
        self.states = {}
        self.transitions = {}
        self.cur_state = None
        self.trans = None

    # adauga o tranzitie
    def add_transistion(self, trans_name, transition):
        self.transitions[trans_name] = transition

    # adauga o stare
    def add_state(self, state_name, state):
        self.states[state_name] = state

    # seteaza starea curenta
    def set_state(self, state_name):
        self.cur_state = self.states[state_name]

    # executa o tranzitie noua
    def to_transition(self, to_trans):
        self.trans = self.transitions[to_trans]

    def execute(self):
        if self.trans:
            self.cur_state.exit()
            self.trans.execute()
            self.set_state(self.trans.to_state)
            self.cur_state.enter()
            self.trans = None
        self.cur_state.execute()

    """
    Cum functioneaza FSM?
    1. Se iese din starea curenta prin "cur_state.exit()"
    2. Se executa intrarea in modul de tranzite
    3. Se seteaza starea curenta in modul "tranzitie"
    4. Se intra in noua stare
    """
