from pfsSPAKE2 import PFS_SPAKE2
from getpass import getpass


def main():
    
    print("Welcome to PFS-SPAKE2 protocol.")
    print("We need to configure the connection before we begin.")
    
    nameInitiator  = input("\nPlease input your username: ")
    namePartnerInitiator = input("Please input the name of your intendent communication partner: ")
    print("Please input your shared-password with your communication partner: ")
    password = getpass()
    print("Please select the desired security level: ")
    print("\t 1. 103 bits of security - ffdhe2048. ")
    print("\t 2. 125 bits of security - ffdhe3072. ")
    print("\t 3. 150 bits of security - ffdhe4096. ")
    secLevel = int(input("Your choice: "))
    
    
    role = "Initiator"
    name = nameInitiator
    partnerName = namePartnerInitiator
    
    #Create the instance for the initiator according to the input the user.
    alice = PFS_SPAKE2(role, secLevel, name, partnerName, password)
    
    
    
    print("\nHello", namePartnerInitiator + ". You have received a connection request from ", nameInitiator + ".")
    print("To proceed with the connection please input your shared password: ")
    password = getpass()
    
    role = "Responder"
    name = namePartnerInitiator
    partnerName = nameInitiator

    
    #Create the instance for the responder according to the input the user.
    bobis = PFS_SPAKE2(role, secLevel, name, partnerName, password)
        
    
    
    msgR1 = alice.doR1()
    msgR2 = bobis.doR2(msgR1)
    msgR3, skAlice = alice.doR3(msgR2)
    skBobis = bobis.doR4(msgR3)
    
    print("\n\nProtocol PFS-SPAKE2 successfully completed. ")
    print("Both parties have mutually authenticated and agreed on the same session key: ")
    print("Alice:\t", skAlice)
    print("Bobis\t", skBobis)
    
    
    

if __name__ == "__main__":
    main()
    