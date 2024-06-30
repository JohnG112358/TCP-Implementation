class TCPState:
    def __init__(self):
        self.state = "CLOSED"
        self.transitions = { # all the states are here, but we only care about the responder side
            "CLOSED": {"PASSIVE_OPEN": "LISTEN"},
            "LISTEN": {"RECEIVE_SYN": "SYN_RECEIVED", "CLOSE": "CLOSED"},
            "SYN_RECEIVED": {"SEND_SYNACK": "SYNACK_SENT"},
            "SYNACK_SENT": {"RECEIVE_ACK": "ESTABLISHED"},
            "ESTABLISHED": {"RECEIVE_FIN": "CLOSE_WAIT", "CLOSE": "FIN_WAIT_1"},
            "CLOSE_WAIT": {"SEND_ACK": "LAST_ACK"},
            "FIN_WAIT_1": {"RECEIVE_FIN_ACK": "FIN_WAIT_2", "RECEIVE_FIN": "CLOSING"},
            "FIN_WAIT_2": {"RECEIVE_FIN": "TIME_WAIT"},
            "CLOSING": {"RECEIVE_FIN_ACK": "TIME_WAIT"},
            "LAST_ACK": {"RECEIVE_ACK": "CLOSED"},
            "TIME_WAIT": {"TIMEOUT": "CLOSED"}
        }
        
    def __str__(self):
        return f"Current state: {self.state}"
    
    def handle_event(self, event):
        if self.state in self.transitions and event in self.transitions[self.state]:
            self.state = self.transitions[self.state][event]
            print(f"Event '{event}' received. Transitioned to {self.state}.")
        else:
            print(f"Event '{event}' not valid from state {self.state}.")
        