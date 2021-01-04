from Crypto.Hash import SHA256


class InverseValidationError(Exception):
    """The inverse of the element could not be found."""



#Encode string in Zq
def encodeStrToZq(stringToEncode, Zq):
    hashObj = SHA256.new(stringToEncode.encode())
    hashInt = int(hashObj.hexdigest(),16)
    hashInt = hashInt % Zq
    return hashInt
    
    

#Find the inverse of a group element "n".
# n_inv = n ^{p-2} mod p, all the exponents are mod q.
def findInverse(n, g, p, q):
    invN = pow (n, (p-2) %q , p)
        
    e  = n * invN % p
        
    if e != 1:
        print ("The inverse of the element cannot be found. Aborting.  ")
        raise InverseValidationError

    return invN