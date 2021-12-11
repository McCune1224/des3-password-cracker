import des_modes as desMode
import passlib.hash as passLib
import time

def _read_file_content(filename : str):
    """Returns a list containing content per line of file"""
    f = open(filename, "r")
    lines = f.readlines()
    f.close()
    return lines

def _clean_hash(hash_line: str):
    """ Clean hash up from string to a list of strings to only contain username, id, left side of hash, and right hash:
     BEFORE  "bozo:1001:CE2390AA223560BBE917F8D6FA472D2C:91AFAADB932D20FFD6A26AD91BE226E8:::"
     AFTER ['bozo', '1001', 'CE2390AA223560BBE917F8D6FA472D2C', '91AFAADB932D20FFD6A26AD91BE226E8']
     """
    #Remove trailing ":::" from string
    clean_hash = hash_line[:len(hash_line)-4] 

    #Divide each item by ":"
    return clean_hash.split(':')

    

def _tobits(plain_string: str):
    """ Take in a string and return the entire bits """
    result = []
    for c in plain_string:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result



def _bitstring_to_bytes(plain_string: str):
    return int(plain_string, 2).to_bytes(len(plain_string) // 8, byteorder='big')

# LM hashes 7 byte half password using DES
def _lmHasher(word):
    """ The word needs 16 char length, so append 0's to the end """
    word.ljust(16, '0')

def _lmHalfHash(password):
    """ lm Hash for one side of the hash """
    password = password.upper()

    # Convert password to bits
    bits = _tobits(password)

    # split bits into groups of size 7 bytes
    byte_array = [bits[i:i+7] for i in range(0, len(bits), 7)]

    # Add 0 to each end of each 7 byte chunk, making it now 8 bytes
    # Return string of all bits
    final_byte_string = ""
    for bit_array in byte_array:
        bit_array.append(0)
        for bit in bit_array:
            final_byte_string += str(bit)

    # Generate key of 64 bytes from string of bits
    key = _bitstring_to_bytes(final_byte_string)

    return desMode.encrypt(b"KGS!@#$%", key)


def bruteForcePasswordCrack(userInfoList: list):
    """ Hash our dictionary word with DES and see if it matches given hash """
    startTime = time.time()
    for word in dictionary_txt:
        # word = "armadillos\n"
       # Remove the '\n' and uppercase the word, uppercase it, and add null padding to 14 chars
        word = word.upper()
        word = word[:-1]
        ogWord = word
        word = word.ljust(14, "\x00")
        # Using DES to create each half of the hash
        leftHash = _lmHalfHash(word[:7]).hex().upper()
        rightHash = _lmHalfHash(word[7:]).hex().upper()

        # if end of word has "s" then we want to check that hash without the "s":
        sWord = ""
        l_sWordHash = r_sWordHash = ""

        if ogWord[-1:] == "S":
            sWord = ogWord[:-1]
            sWord = sWord.ljust(14, "\x00")
            l_sWordHash = _lmHalfHash(sWord[:7]).hex().upper()
            r_sWordHash = _lmHalfHash(sWord[7:]).hex().upper()

        print(ogWord)

        # Check to see if both hashes match
        if (leftHash+rightHash == userInfoList[2]):
            solvedPassword = word.lower()
            endTime = time.time()
            print("\nPASSWORD FOUND!!(took {0} seconds to brute force)\nUSERNAME: ".format(
                round((endTime-startTime), 2)) + userInfoList[0] + "\nPASSWORD: " + solvedPassword)
            return(solvedPassword.lower())

        elif(l_sWordHash+r_sWordHash == userInfoList[2]):
            solvedPassword = sWord.lower()
            endTime = time.time()
            print("\nPASSWORD FOUND!!(took {0} seconds to brute force)\nUSERNAME: ".format(
                round((endTime-startTime), 2)) + userInfoList[0] + "\nPASSWORD: " + solvedPassword.lower())
            return(solvedPassword.lower())
    print("No Password Found...")
    return "No Password Found..."



#The main difference between this function and brutrForcePasswordCrack() is that 
#This checks the left side of the hash first and if it doesn't match the firsth half
#of the user's hash we got, skip the word since it clearly isn't even close to being it
def complexPasswordCrack(userInfoList):
    """ Optimized version for Password Cracker

        The main difference between this function and brutrForcePasswordCrack() is that 
        This checks the left side of the hash first and if it doesn't match the firsth half
        of the user's hash we got, skip the word since it clearly isn't even close to being it
"""
    startTime = time.time()
    #Get the user's password hash to compare our hash to later
    passwordHash = userInfoList[2]
    userLeftHash = userInfoList[2][0:len(userInfoList[2])//2]
    userRightHash = userInfoList[2][len(
        userInfoList[2])//2:len(userInfoList[2])]

    #Instead of trying numbers 0-9 for 3 digits which would take 1000 times longer for us to solve,
    #just try a bunch of common numbers people use for their passwords.
    #All of the common numbers in passwords we used was found here: https://en.wikipedia.org/wiki/List_of_the_most_common_passwords
    commonNumbers = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16",
                     "000", "111", "222", "333", "444", "555", "666", "777", "888", "999", "123", "456", "789", "123", "121"]
    #Go through each dictionary word
    for word in dictionary_txt:
        # word = "corvettes\n"
        print(word)
        # remove \n and make uppercase
        word = word[:-1].upper()
        # copy of word before padding
        ogWord = word

        # if end of word has "s" then we want to check that hash without the "s":
        sWord = ""
        l_sWordHash = r_sWordHash = ""
        if word[-1:] == "S":
            sWord = ogWord
            sWord.ljust(14, "\x00")
            l_sWord = word[:7].ljust(7, "\x00")
            l_sWordHash = _lmHalfHash(l_sWord).hex().upper()

        #left side of word, add padding incase its a lenght less of 7
        leftSide = word[:7].ljust(7, "\x00")
        # If the left side of the hash doesn't match the left side of the hash of the hash we
        # recieved from userinfo, move to the next word since we know its not the correct word
        if userLeftHash != _lmHalfHash(leftSide).hex().upper():
            continue

        #now that we know what the left is, add all of these numbers to the left half of the words
        #that it could possibly and hash them
        for num in commonNumbers:
            # If there is no "S" at the end of the word
            if sWord == "":
                rightSide = (word[7:]+num).ljust(7, "\x00")
                rightHash = _lmHalfHash(rightSide).hex().upper()
                #Does the number we added to the word match the hash?
                if rightHash == userRightHash:
                    solvedPassword = (word+num).lower()
                    endTime = time.time()
                    print("\nPASSWORD FOUND!!(took {0} seconds to brute force)\nUSERNAME: ".format(
                        round((endTime-startTime), 2)) + userInfoList[0] + "\nPASSWORD: " + solvedPassword)
                    return(solvedPassword.lower())
            #If there is an "S" at the end of the word
            else:
                rightSide = (word[7:-1] + num).ljust(7, "\x00")
                rightHash = _lmHalfHash(rightSide).hex().upper()
                #Does the number we added to the word match the hash?
                if rightHash == userRightHash:
                    solvedPassword = (word[:-1]+num).lower()
                    endTime = time.time()
                    print("\nPASSWORD FOUND!!(took {0} seconds to brute force)\nUSERNAME: ".format(
                        round((endTime-startTime), 2)) + userInfoList[0] + "\nPASSWORD: " + solvedPassword)
                    return(solvedPassword.lower())



if __name__ == '__main__':
    hash_txt = _read_file_content("pwtext.txt")
    dictionary_txt = _read_file_content("dictionary.txt")

    user1 = _clean_hash(hash_txt[0])
    user2 = _clean_hash(hash_txt[1])
    user3 = _clean_hash(hash_txt[2])
    #bozoPassword = bruteForcePasswordCrack(user1)
    tallmanPassword = complexPasswordCrack(user2)
