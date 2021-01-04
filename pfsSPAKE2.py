#   This is this the implementation of the PFS-SPAKE2 protocol.
#   Protocol available at 
#   Impletemtation by Jose Lopez Becerra

from publicParam import publicParam
from Crypto.Random import random
from Crypto.Hash import SHA256
from groupOperations import *


    
class AthenticationError(Exception):
    """The parties cannot be authenticated."""
    pass
    
    
class RoleError(Exception):
    """The party received an unexpected message."""
    pass


class PFS_SPAKE2:
    def __init__(self, role, secLevel, name, partnerName, passwd):
        
        #Initializa parameters according to the desired security level.
        self.pp = publicParam(secLevel)
        self.g = self.pp.getG()
        self.p = self.pp.getP()
        self.q = self.pp.getQ()
        self.M = self.pp.getM()
        
        self.name = name
        self.role = role
        self.partnerName = partnerName
        self.passwdZq = encodeStrToZq(passwd, self.q)
        
        
        #The following are ephemeral keys,  must accessible only the party who generates it during a protocol run. 
        self.x = 0
        self.y = 0
        
        #These terms are exchanged during the protocol execution (not private)
        self.X_Term = 0
        self.Y = 0

        
        
    def doR1(self):
        
        if self.role != "Initiator":
            raise RoleError
        
        #Retrieve public parameters
        g = self.g
        p = self.p
        q = self.q
        M = self.M
        
        
        #Retrieve own values (secret, self-computed, or both)
        passwdZq = self.passwdZq
        
        #Compute as required for R1
        x = random.randint(0,q)
        X = pow(g, x % q, p)
        
        M1 = pow (M, passwdZq, p)
        X_Term = X * M1 % p
   
        
        #Store computed values for next rounds
        self.x = x
        self.X_Term = X_Term
        
        return (self.name, X_Term)
        
        
        
    def doR2(self, msgR1):
        
        #ToDo validate group element
        
        
        if self.role != "Responder":
            raise RoleError
            
            
        #Retrieve from message msgR1 received
        partnerName = msgR1[0]
        partnerX_Term= msgR1[1]
        
        if self.partnerName  != partnerName:
            raise RoleError
            
        
        #Retrieve public parameters
        g = self.g
        p = self.p
        q = self.q
        M = self.M
        
        #Retrieve own values (secret, self-computed, or both)
        passwdZq = self.passwdZq
  
  

        #Compute as required for R2
        y = random.randint(0,q)
        Y = pow(g, y % q, p)

        M1 = pow (M, passwdZq, p)
        invM1 = findInverse(M1, g, p, q)
        sigma = pow(partnerX_Term*invM1 %p, y, p)

        
        #k1 = H1(C, S, X^*, Y, sigma, passwd)
        msgToHash = "1" + self.partnerName + self.name + str(partnerX_Term) + str(Y) + str(sigma) + str(passwdZq)
        hashObj = SHA256.new(msgToHash.encode())
        k1  = str(hashObj.hexdigest())

        
        #Store computed values for next rounds
        self.partnerX_Term = partnerX_Term
        self.y = y
        self.Y = Y
        self.sigma = sigma
        
        return (self.name, Y, k1)
        
    
    
    
    def doR3(self, msgR2):
        #ToDo validate group element
        
        if self.role != "Initiator":
            raise RoleError
            
        #Retrieve from message msgR1 received
        partnerName = msgR2[0]
        Y = msgR2[1]
        k1 = msgR2[2]
        
        if self.partnerName  != partnerName:
            raise RoleError
         
        #Retrieve public parameters
        g = self.g
        p = self.p
        q = self.q
        M = self.M

        
        #Retrieve own values (secret, previously self-computed, or both)
        passwdZq = self.passwdZq
        x = self.x
        X_Term = self.X_Term
        
        
        #1. Validate key-confirmation code 'k1' received. Is k1 =? H1(C, S, X^*, Y, sigma, passwd)
        sigma = pow(Y, x, p)
        msgToHash = "1" + self.name + self.partnerName + str(X_Term) + str(Y) + str(sigma) + str(passwdZq)
        hashObj = SHA256.new(msgToHash.encode())
        k1_computed  = str(hashObj.hexdigest())
        
        
        if k1 != k1_computed:
            print("Procol could not terminate, authentication did not succeed.")
            self.deleteVariables()
            raise AthenticationError
        
        #2. Compute key-confirmation code k2, and session key k3.
        else:
            msgToHash = "2" + self.name + self.partnerName + str(X_Term) + str(Y) + str(sigma) + str(passwdZq)
            hashObj = SHA256.new(msgToHash.encode())
            k2  = str(hashObj.hexdigest())
            
            msgToHash = "3" + self.name + self.partnerName + str(X_Term) + str(Y) + str(sigma) + str(passwdZq)
            hashObj = SHA256.new(msgToHash.encode())
            k3  = int(hashObj.hexdigest(),16)
        
        self.deleteVariables()
        return k2, k3
        
        
        
    def doR4(self, msgR3):
        
        if self.role != "Responder":
            raise RoleError
        
        #Retrieve public parameters, or received in previous rounds (still public)
        partnerX_Term = self.partnerX_Term
        partnerName = self.partnerName
        
        
        #Retrieve own values (secret, previously self-computed, or both)
        Y = self.Y
        sigma = self.sigma
        passwdZq = self.passwdZq
        
        
        #Retrieve from message msgR3 received
        k2 = msgR3

        
        #1. Validate key-confirmation code 'k2' received. 
        #k2 = H2(C, S, X^*, Y, sigma, passwd)
        msgToHash = "2" + self.partnerName + self.name + str(partnerX_Term) + str(Y) + str(sigma) + str(passwdZq)
        hashObj = SHA256.new(msgToHash.encode())
        k2_computed  = str(hashObj.hexdigest())
        
        
        if k2 != k2_computed:
            print("Procol could not terminate, authentication did not suceed.")
            self.deleteVariables()
            raise AthenticationError
        
        else:
            msgToHash = "3" + self.partnerName + self.name + str(partnerX_Term) + str(Y) + str(sigma) + str(passwdZq)
            hashObj = SHA256.new(msgToHash.encode())
            k3  = int(hashObj.hexdigest(), 16)
        
        self.deleteVariables()
        return k3
        
           
        
        
    def deleteVariables(self):
        #Delete all variables, when protocol finishes or exception raised 
        self.x = 0
        self.y = 0
        self.X_Term = 0
        self.Y = 0
        