##
# Stegalyze - Python Image Steganography & Steganalysis
# Copyright (C) 2012 Marc Budofsky
# Version 1.0
#
# Modified from: Stepic <http://domnit.org/stepic/doc/pydoc/stepic.html>
#                stegano-cb <http://code.google.com/p/stegano-cb/>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
##

#---Imports-------------------------------------------------------------
import os
import sys
import random as rnd
from PIL import Image
from optparse import OptionParser

#---Globals-------------------------------------------------------------
debug = False

#---Functions-----------------------------------------------------------
def random_encode_data(image, data):
    datalen = len(data)
    
    cntImage = 0
    
    for i in xrange(datalen):
        pixels = [value & ~1 for value in image[cntImage]]
        byte = ord(data[i])
        for j in xrange(7, -1, -1):
            if debug: print str(j) + ": Bit > " + str(byte & 1) + ", Current Pixel" + str(pixels[j])
            pixels[j] |= byte & 1
            byte >>= 1
            if debug: print str(j) + ": New Pixel" + str(pixels[j])
        if i == datalen - 1:
            pixels[-1] |= 1
        pixels = tuple(pixels)
        yield pixels[0:3]
        yield pixels[3:6]
        yield pixels[6:9]
        
        cntImage += 1

def encode_data(image, data):
    imdata = iter(image)
    datalen = len(data)
    
    for i in xrange(datalen):
        pixels = [value & ~1 for value in
                    imdata.next()[:3] + imdata.next()[:3] + imdata.next()[:3]]
        byte = ord(data[i])
        for j in xrange(7, -1, -1):
            pixels[j] |= byte & 1
            byte >>= 1
        if i == datalen - 1:
            pixels[-1] |= 1
        pixels = tuple(pixels)
        yield pixels[0:3]
        yield pixels[3:6]
        yield pixels[6:9]

def random_encode(image, key, data):
    '''
    Generate a stego image by pseudorandomly inserting message
    '''
    
    if debug: print 'Encode...'
    
    img = image.copy()
    rnd.seed(key)
    
    datalen = len(data)
    if datalen == 0:
        raise ValueError('No Message Data')
        return
    if datalen * 3 > len(img.getdata()):
        raise ValueError('Message is too large for Image')
        return
    
    usedPixels = list()
    setPixels  = list()
    
    w = img.size[0] - 1
    h = img.size[1] - 1
    
    for cnt in xrange((len(data))):
        pixels = list()
        for z in xrange(3):
            while True:
                tmp = (rnd.randint(0, w), rnd.randint(0, h))
                if tmp not in usedPixels:
                    (x, y) = tmp
                    usedPixels.append(tmp)
                    pixel = image.getpixel((x,y))
                    for bar in xrange(3):
                        pixels.append(pixel[bar])
                    break
        setPixels.append(pixels)
	
    coordCnt = 0
    pixelCnt = 0
    for pixel in random_encode_data(setPixels, data):
        coord = usedPixels[coordCnt]
        oldPixel = img.getpixel(coord)
        if len(oldPixel) == 4: oldPixel = oldPixel[:-1]
        img.putpixel(coord, pixel)
        newPixel = pixel
        if debug: print str(coord) + ": " + str(oldPixel) + " --> " + str(newPixel)
        coordCnt += 1
        if coordCnt == len(usedPixels):
            break
            
    return img

def encode(image, data):
    if debug: print 'Encode...'
    
    img = image.copy()
    
    datalen = len(data)
    if datalen == 0:
        raise ValueError('No Message Data')
        return
    if datalen * 3 > len(img.getdata()):
        raise ValueError('Message is too large for Image')
        return
    
    w = image.size[0]
    (x, y) = (0, 0)
    for pixel in encode_data(img.getdata(), data):
        oldPixel = img.getpixel((x,y))
        if len(oldPixel) == 4: oldPixel = oldPixel[:-1]
        img.putpixel((x, y), pixel)
        newPixel = pixel
        if debug: print str((x,y)) + ": " + str(oldPixel) + " --> " + str(newPixel)
        if x == w - 1:
            x = 0
            y += 1
        else:
            x += 1
	
    return img

def random_decode_data(image, key, attack):
	imdata = iter(image)
	rnd.seed(key)
	
	usedPixels = set()
	
	w = image.size[0] - 1
	h = image.size[1] - 1
	
	while True:
		pixels = list()
		for z in xrange(3):
			while True:
				tmp = (rnd.randint(0, w), rnd.randint(0, h))
				if tmp not in usedPixels:
					(x, y) = tmp
					usedPixels.add(tmp)
					pixel = image.getpixel((x,y))
					for bar in xrange(3):
						pixels.append(pixel[bar])
					break
		if debug: print pixels
		byte = 0
		for c in xrange(7):
			byte |= pixels[c] & 1
			byte <<= 1
		byte |= pixels[7] & 1
		yield chr(byte)
		if pixels[-1] & 1:
			break

def decode_data(image):
	img = iter(image)
	
	while True:
		pixels = list(img.next()[:3] + img.next()[:3] + img.next()[:3])
		byte = 0
		for c in xrange(7):
			byte |= pixels[c] & 1
			byte <<= 1
		byte |= pixels[7] & 1
		yield chr(byte)
		if pixels[-1] & 1:
			break

def decode(image, key):
	if debug: print 'Decode...'
	
	if key == '':
		stego = ''.join(decode_data(image.getdata()))
	else:
		stego = ''.join(random_decode_data(image.getdata(), key, False))
	if debug: print stego
	return stego

def steganalyse(img):
	"""
	Steganlysis of the LSB technique.
	"""
	encoded = img.copy()
	width, height = img.size
	bits = ""
	pCnt = 0;
	for row in range(height):
		for col in range(width):
			r, g, b = img.getpixel((col, row))
			r = 0 if (r % 2 == 0) else 255
			g = 0 if (g % 2 == 0) else 255
			b = 0 if (b % 2 == 0) else 255
			if debug: print '(col, row), (r,g,b) = (' + str(col) + ',' + str(row) + '), (' + str(r) + ',' + str(g) + ',' + str(b) + ')'
			encoded.putpixel((col, row), (r, g , b))
	
	return encoded
	

def dictionary_attack(image):
	words = open('words', 'r').read().split("\n")
	if debug: print "Dictionary Length:", len(words)
	
	keys = sorted(words, key=len);
	msg_len = 0
	bestkey = ""
	
	for k in keys:
		text = ''.join(random_decode_data(image.getdata(), k, True))
		if len(text) > msg_len:
			msg_len = len(text)
			bestkey = k
	
	return bestkey

def vigenere(key, data, mode):
	punctuation = ['.',',','!','\'','"',' ','&','%',')','(','@','#','$','%','^','*']
	
	if (mode == 'encrypt'):
		print 'Encrypt...',
		
		plaintext = data
		ciphertext = ''
		isCaps = False
		key_loc = 0
		
		for cnt in xrange(len(plaintext)):
			if plaintext[cnt] not in punctuation:
				if plaintext[cnt] >= 'A' and plaintext[cnt] <= 'Z':
					isCaps = True
					let = (ord(plaintext[cnt]) + 32) - 97
				else: let = ord(plaintext[cnt]) - 97
				shift = ord(key[key_loc]) - 97
				let = (let + shift) % 26
				if (isCaps): let -= 32
				ciphertext += chr(let + 97)
				isCaps = False
				key_loc = (key_loc + 1) % len(key)
			else:
				ciphertext += plaintext[cnt]
			
		print ciphertext
		return ciphertext
		
	else:	# mode == 'decrypt'
		print 'Decrypt...',
		
		ciphertext = data
		plaintext = ''
		isCaps = False
		key_loc = 0
		
		for cnt in xrange(len(ciphertext)):
			if ciphertext[cnt] not in punctuation:
				if ciphertext[cnt] >= 'A' and ciphertext[cnt] <= 'Z':
					isCaps = True
					let = (ord(ciphertext[cnt]) + 32) - 97
				else: let = ord(ciphertext[cnt]) - 97
				shift = ord(key[key_loc]) - 97
				let = (let - shift)
				if (let < 0): let += 26
				if (isCaps): let -= 32
				plaintext += chr(let + 97)
				isCaps = False
				key_loc = (key_loc + 1) % len(key)
			else:
				plaintext += ciphertext[cnt]
			
		return plaintext
        
def runInteractive():
    os.system('clear')
    while True:
        print "---Stegalyze Menu-----------------------------------------------------"
        print "\t1. Encode"
        print "\t2. Decode"
        print "\t3. Analyze"
        print "\t4. Toggle Debug Mode"
        print "\t0. Exit"
        print "----------------------------------------------------------------------"
        menuOption = int(raw_input("Selection: "))
        
        if menuOption == 1:
            print "\nEncode an Image"
            imgFilename = raw_input("Cover Image File: ")
            try:
                imgFile = Image.open(imgFilename)
            except IOError:
                print "The file '" + imgFilename + "' could not be opened."
                continue
			
            useEncryption = raw_input("Encrypt Message (Y/N): ")
            while useEncryption.lower() != 'y' and useEncryption.lower() != 'n':
                useEncryption = raw_input("Encrypt Message (Y/N): ")
            if useEncryption.lower() == 'y':
                encryptionKey = raw_input(" Encryption Key: ")
            rndKey = raw_input("Random Key: ")
            userMsg = raw_input("Message: ")
            if '.txt' in userMsg:
                try:
                    msgText = open(userMsg, "r").read()
                except IOError:
                    print "The file '" + userMsg + "' could not be opened."
                    continue
            else:
                msgText = userMsg
			
            if rndKey == '':
                if useEncryption.lower() == 'y':
                    encodedImg = encode(imgFile, vigenere(encryptionKey, msgText, 'encrypt'))
                else:
                    encodedImg = encode(imgFile, msgText)
            else:
                if useEncryption.lower() == 'y':
                    encodedImg = random_encode(imgFile, rndKey, vigenere(encryptionKey, msgText, 'encrypt'))
                else:
                    encodedImg = random_encode(imgFile, rndKey, msgText)
            
            saveTo = raw_input("Encoded Image Filename: ")
            if saveTo != "":
                if saveTo.find(".png") == -1: saveTo += ".png"
                encodedImg.save(saveTo)
        elif menuOption == 2:
            print "\nDecode an Image"
            encodedImgFilename = raw_input("Stego Image File: ")
            try:
                imgFile = Image.open(encodedImgFilename)
            except IOError:
                print "The file '" + encodedImgFilename + "' could not be opened."
                continue
			
            useEncryption = raw_input("Is Message Encrypted? (Y/N): ")
            while useEncryption.lower() != 'y' and useEncryption.lower() != 'n':
                useEncryption = raw_input("Is Message Encrypted? (Y/N): ")
            if useEncryption.lower() == 'y':
                encryptionKey = raw_input("Encryption Key: ")
            rndKey = raw_input("Stego Key: ")
			
            if useEncryption.lower() == 'y':
                print vigenere(encryptionKey, decode(imgFile, rndKey), 'decrypt')
            else:
                print decode(imgFile, rndKey)
			
        elif menuOption == 3:
            print "\nAnalyze an Image"
            encodedImgFilename = raw_input("Stego Image File: ")
            try:
                imgFile = Image.open(encodedImgFilename)
            except IOError:
                print "The file '" + encodedImgFilename + "' could not be opened."
                continue
            
            analysisImg = steganalyse(imgFile)
            analysisImg.show()
            saveTo = raw_input("Analyzed Image Filename: ")
            if saveTo != "":
                if saveTo.find(".png") == -1: saveTo += ".png"
                analysisImg.save(saveTo)
            
            attemptDecode = raw_input("Based on the Analysis, attempt to decode? (Y/N): ")
            while attemptDecode.lower() != 'y' and attemptDecode.lower() != 'n':
                attemptDecode = raw_input(" Based on the Analysis, attempt to decode? (Y/N): ")
            if attemptDecode.lower() == 'y':
                useBruteForce = raw_input("Does it look like a dictionary attack is needed? (Y/N): ")
                while useBruteForce.lower() != 'y' and useBruteForce.lower() != 'n':
                    useBruteForce = raw_input("Does it look like a dictionary attack is needed? (Y/N): ")
                if useBruteForce.lower() == 'y':
                    guessedKey = dictionary_attack(imgFile)
                    if (guessedKey == False):
                        print "The key could not be found."
                    else:
                        print "The key appears to be '" + guessedKey + "'"
                        print "The message is:\n" + decode(imgFile, guessedKey)
                else:
                    print "The message is:\n" + decode(imgFile, '')
        elif menuOption == 4:
            debug = not debug
            print 'Debug Mode is now ' + ('On' if debug else 'Off')
        elif menuOption == 0:
            break
        else:
            print 'Invalid Option'
    os.system('clear')
    
def addParserOptions(parser):
    parser.add_option("-e", "--encode",
                        action="store_true",
                        dest="encode",
                        default=False,
                        help="Encode an Image")
    parser.add_option("-d", "--decode",
                        action="store_true",
                        dest="decode",
                        default=False,
                        help="Decode an Image")
    parser.add_option("-a", "--analyze",
                        action="store_true",
                        dest="analyze",
                        default=False,
                        help="Analyze an Image")
    parser.add_option("--encrypt",
                        action="store",
                        dest="encryptionKey",
                        default="",
                        help="Encryption Key")
    parser.add_option("--rnd",
                        action="store",
                        dest="rndKey",
                        default="",
                        help="Random Key")
    parser.add_option("--debug",
                        action="store_true",
                        dest="debug",
                        default="",
                        help="Enable Debug Output")

if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [options] image <message>", version="%prog 1.0")
    addParserOptions(parser)
    (options, args) = parser.parse_args()
    
    if options.debug:
        debug = True
    
    if options.encode or options.decode or options.analyze:
        try:
            imgFile = Image.open(args[0])
        except IOError:
            print "The image '" + args[0] + "' could not be opened."
            sys.exit(-1)
    
    if options.encode:
        if ".txt" in args[1]:
            try:
                msgText = open(args[1], "r").read()
            except IOError:
                print "The file '" + args[1] + "' could not be opened."
                sys.exit(-1)
        else:
            msgText = args[1]
        if options.rndKey == '':
            if options.encryptionKey != "":
                encodedImg = encode(imgFile, vigenere(options.encryptionKey, msgText, 'encrypt'))
            else:
                encodedImg = encode(imgFile, msgText)
        else:
            if options.encryptionKey != "":
                encodedImg = random_encode(imgFile, options.rndKey, vigenere(options.encryptionKey, msgText, 'encrypt'))
            else:
                encodedImg = random_encode(imgFile, options.rndKey, msgText)
        encodedImg.save("StegoImg.png")
        print "Encode Complete. Saved to 'StegoImg.png'" 
    elif options.decode:
        if options.encryptionKey != "":
            print vigenere(options.encryptionKey, decode(imgFile, options.rndKey), 'decrypt')
        else:
            print decode(imgFile, options.rndKey)
        print "Decode Complete."
    elif options.analyze:
        analysisImg = steganalyse(imgFile)
        analysisImg.save("StegoAnalysis.png")
        print "Analysis Complete. Saved to 'StegoAnalysis.png'"
    else:
        runInteractive()