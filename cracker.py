import des_modes as desMode
#passlib.hash was used for testing purposes before implementing DES, not in final version but was frequently used to 
#help build a lot of the code before the personal DES implimentation. 
#passLib.lmhash.hash(word) was really the only thing used for testing
import passlib.hash as passLib
import time
# Read both of the text files for their respective info and store each line in a list
f = open("pwtext.txt", "r")
passwordLines = f.readlines()
f.close()

f = open("dictionary.txt", "r")
dictionaryWords = f.readlines()
f.close()

# make a list to store the values in and snip off the whitespaces, \n, and 2nd number in the list
user1 = passwordLines[0].split(':')

user2 = passwordLines[1].split(':')

user3 = passwordLines[2].split(':')
#There was probably a clearner way to remove enteries from the list, but this worked and took few lines of code...
#Just deletes any useless info, the second number and the extra blank words at the end of the list to be specific.
# bozo:1001:CE2390AA223560BBE917F8D6FA472D2C:91AFAADB932D20FFD6A26AD91BE226E8:::
# tallman:1002:D3CC6BB953241B61EFB303C2F126705E:8C219140EF269E446F982AD0FD989AC1:::
# zerocool:500:6F3989F97ADB6701C2676C7231D0B1B5:4BCA5C033CC8A87FF18696E7F35DE514:::
for i in range(1, 3):
    if i == 1:
        del user1[i]
        del user2[i]
        del user3[i]
    del user1[-i]
    del user2[-i]
    del user3[-i]



#Luke Frisbee Helped me out a lot for the padding required before passing our code 
#into DES. The actual DES code is my own but this padding is mainly from him.

def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result

# Convert string of bits to bytes


def bitstring_to_bytes(s):
    return int(s, 2).to_bytes(len(s) // 8, byteorder='big')

# LM hashes 7 byte half password using DES

def lmHasher(word):
    word.ljust(16, '0')

def lmHalfHash(password):
    password = password.upper()

    # Convert password to bits
    bits = tobits(password)

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
    key = bitstring_to_bytes(final_byte_string)

    return desMode.encrypt(b"KGS!@#$%", key)


def bruteForcePasswordCrack(userInfoList):
    startTime = time.time()
    for word in dictionaryWords:
        # word = "armadillos\n"
       # Remove the '\n' and uppercase the word, uppercase it, and add null padding to 14 chars
        word = word.upper()
        word = word[:-1]
        ogWord = word
        word = word.ljust(14, "\x00")
        # Using DES to create each half of the hash
        leftHash = lmHalfHash(word[:7]).hex().upper()
        rightHash = lmHalfHash(word[7:]).hex().upper()

        # if end of word has "s" then we want to check that hash without the "s":
        sWord = ""
        l_sWordHash = r_sWordHash = ""

        if ogWord[-1:] == "S":
            sWord = ogWord[:-1]
            sWord = sWord.ljust(14, "\x00")
            l_sWordHash = lmHalfHash(sWord[:7]).hex().upper()
            r_sWordHash = lmHalfHash(sWord[7:]).hex().upper()

        print(ogWord)

        # Check to see if both hashes match
        if (leftHash+rightHash == userInfoList[1]):
            solvedPassword = word.lower()
            endTime = time.time()
            print("\nPASSWORD FOUND!!(took {0} seconds to brute force)\nUSERNAME: ".format(
                round((endTime-startTime), 2)) + userInfoList[0] + "\nPASSWORD: " + solvedPassword)
            return(solvedPassword.lower())

        elif(l_sWordHash+r_sWordHash == userInfoList[1]):
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
    startTime = time.time()
    #Get the user's password hash to compare our hash to later
    passwordHash = userInfoList[1]
    userLeftHash = userInfoList[1][0:len(userInfoList[1])//2]
    userRightHash = userInfoList[1][len(
        userInfoList[1])//2:len(userInfoList[1])]

    #Instead of trying numbers 0-9 for 3 digits which would take 1000 times longer for us to solve,
    #just try a bunch of common numbers people use for their passwords.
    #All of the common numbers in passwords we used was found here: https://en.wikipedia.org/wiki/List_of_the_most_common_passwords
    commonNumbers = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16",
                     "000", "111", "222", "333", "444", "555", "666", "777", "888", "999", "123", "456", "789", "123", "121"]
    #Go through each dictionary word
    for word in dictionaryWords:
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
            l_sWordHash = lmHalfHash(l_sWord).hex().upper()

        #left side of word, add padding incase its a lenght less of 7
        leftSide = word[:7].ljust(7, "\x00")
        # If the left side of the hash doesn't match the left side of the hash of the hash we
        # recieved from userinfo, move to the next word since we know its not the correct word
        if userLeftHash != lmHalfHash(leftSide).hex().upper():
            continue

        #now that we know what the left is, add all of these numbers to the left half of the words
        #that it could possibly and hash them
        for num in commonNumbers:
            # If there is no "S" at the end of the word
            if sWord == "":
                rightSide = (word[7:]+num).ljust(7, "\x00")
                rightHash = lmHalfHash(rightSide).hex().upper()
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
                rightHash = lmHalfHash(rightSide).hex().upper()
                #Does the number we added to the word match the hash?
                if rightHash == userRightHash:
                    solvedPassword = (word[:-1]+num).lower()
                    endTime = time.time()
                    print("\nPASSWORD FOUND!!(took {0} seconds to brute force)\nUSERNAME: ".format(
                        round((endTime-startTime), 2)) + userInfoList[0] + "\nPASSWORD: " + solvedPassword)
                    return(solvedPassword.lower())


if __name__ == '__main__':
    bozoPassword = bruteForcePasswordCrack(user1)
    tallmanPassword = complexPasswordCrack(user2)
