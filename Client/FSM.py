class TCPState:
    def __init__(self):
        self.state = "CLOSED"
        self.transitions = {
            "CLOSED": {"ACTIVE_OPEN": "SYN_SENT"},
            "SYN_SENT": {"RECEIVE_SYN_ACK": "ESTABLISHED", "RECEIVE_FIN": "CLOSE_WAIT"},
            "ESTABLISHED": {"CLOSE": "FIN_WAIT_1", "RECEIVE_FIN": "CLOSE_WAIT"},
            "FIN_WAIT_1": {"RECEIVE_FIN": "CLOSING", "RECEIVE_FIN_ACK": "FIN_WAIT_2", "RECEIVE_ACK": "FIN_WAIT_2"},
            "FIN_WAIT_2": {"RECEIVE_FIN": "TIME_WAIT"},
            "CLOSING": {"RECEIVE_FIN_ACK": "TIME_WAIT"},
            "CLOSE_WAIT": {"SEND_FIN": "LAST_ACK"},
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
