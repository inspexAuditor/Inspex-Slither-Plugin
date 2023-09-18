
class PrivilegeList:

    def __init__(self):
        self.modifiers = []
        self.isUsePrivilegeList = False

    def getPrivilegedModifiers(self):
        return self.modifiers

    def setPrivilegedModifiers(self, _modifiers):
        self.isUsePrivilegeList = True
        self.modifiers = _modifiers