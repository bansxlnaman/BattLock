class SessionManager:

    def __init__(self):

        self.sessions = {}

    def add_session(self, session_id, battery_id):

        self.sessions[session_id] = battery_id

    def session_exists(self, session_id):

        return session_id in self.sessions

    def get_battery(self, session_id):

        return self.sessions.get(session_id)
