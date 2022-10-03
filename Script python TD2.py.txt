import hashlib
import secrets
from textwrap import wrap
from backports.pbkdf2 import pbkdf2_hmac
import binascii
import ecdsa
import codecs
import time

#Créer un programme python interactif en ligne de commande


def Derivation(priv_key,pub_key, chaincode, index, deriv):
    
    if (deriv==0):
        return priv_key
    else:
        
        prehash_child=public_key+chaincode+index
        hashed=hashlib.sha256(prehash_child.encode('utf-8')).hexdigest()
        salt_3=binascii.unhexlify(hashed)
        child_code = pbkdf2_hmac("sha512", password, salt_3, 2048, 64)
        child_code=binascii.hexlify(child_code)
        child_code=bin(int(child_code,16))[2:]
        while(len(child_code)<512):
            child_code='0'+child_code
            
        child_private_key=child_code[:256]
        child_chaincode=child_code[256:]
        
        child_private_key2=hex(int(child_private_key,2))
        child_private_key2 = codecs.decode(child_private_key2[2:], 'hex')
        public_key_raw = ecdsa.SigningKey.from_string(child_private_key2, curve=ecdsa.SECP256k1).verifying_key
        public_key_bytes = public_key_raw.to_string()
        
        public_key_hex = codecs.encode(public_key_bytes, 'hex')
        pub_key=bin(int(public_key_hex,16))[2:]
        deriv=deriv-1
        return Derivation(child_private_key,pub_key, child_chaincode, index, deriv)
    

print()
print("TD2 Veuillez entrer le numéro de la question souhaitée ou entrer 'exit' pour quitter")
print("1: BIP39 Seed aléatoire")
print("2: BIP39 Import d'une seed mnémonique")
print("3: BIP32 Master private key & Chaincode d'un seed random, Master Public key et Child Key")
choice=input()

while(choice!="exit"):
    
    print("You selected:",choice)
    
    #%%
    if(choice=="1"):
        
        #Créer un entier aléatoire pouvant servir de seed à un wallet de façon sécurisée
        
        random_number=secrets.randbits(130)
        binary_random_number=bin(random_number)

        while(len(binary_random_number)!=130):
            random_number=secrets.randbits(130)
            binary_random_number=bin(random_number)
    
        #Représenter cette seed en binaire et le découper en lot de 11 bits 
    
        print("\nL'entier aléatoire de 128 bits est :",random_number)
        binary_random_number=binary_random_number[2:]
        print("\nConverti en binaire :",binary_random_number)

        hash_rdm_nbr=hashlib.sha256(binary_random_number.encode('utf-8')).hexdigest()
        print("\nHashé:",hash_rdm_nbr)
        hash_rdm_nbr=bin(int(hash_rdm_nbr,16))[2:]
        entropy=binary_random_number+hash_rdm_nbr[0:4]
        print("\nSeed sécurisé :",entropy)
        
        tab_entro=wrap(entropy, 11)
        print("\nSéparés en 11 blocs",tab_entro)
        
        #Attribuer à chaque lot un mot selon la liste BIP 39 et afficher la seed en mnémonique
        
        f=open(r'word.txt','r')
        liste_mots=f.readlines()
        tab_mots=[]
        for x in tab_entro:
            x=int(x,2)
            tab_mots.append(liste_mots[x].strip("\n"))
        print("\nSoit la seed mnémonique correspondante",tab_mots)
        
    #%%    
    elif(choice=="2"):
        
        #Permettre l’import d’une seed mnémonique
        
        print("\nVeuillez entrer votre clé mnémonique :")
        mnemo_seed=input()
        mnemo_seed=mnemo_seed.lower()
        mnemo_tab=mnemo_seed.split()
        f=open('./word.txt','r')
        liste_mots=f.readlines()
        for j in range(len(liste_mots)):
            liste_mots[j]=liste_mots[j].strip("\n")
        
        entro_tab=[]
        for i in mnemo_tab:
            ind=liste_mots.index(i)
            entro_tab.append(bin(ind)[2:])
        for k in range(len(entro_tab)):
            while(len(entro_tab[k])<11):
                entro_tab[k]="0"+entro_tab[k]
        binary_seed=''
        for a in entro_tab:
            binary_seed+=a
        print("\nSeed en binaire :",binary_seed)
        seed=int(binary_seed[:-4],2)
        print("\nSeed : ",seed)
        
    #%%    
    elif(choice=='3'):
        
        #Extraire la master private key et le chain code
        
        random_number2=secrets.randbits(130)
        binary_random_number2=bin(random_number2)
        print("\nSeed random:", random_number2)
        time.sleep(1)
        while(len(binary_random_number2)!=130):
            random_number2=secrets.randbits(130)
            binary_random_number2=bin(random_number2)
            
        binary_random_number2=binary_random_number2[2:]
        salt=hashlib.sha256(binary_random_number2.encode('utf-8')).hexdigest()

        salt_bis=binascii.unhexlify(salt)
        password="123456789101".encode('utf-8')
        key = pbkdf2_hmac("sha512", password, salt_bis, 2048, 64)
        key=binascii.hexlify(key)
        key=bin(int(key,16))[2:]
        while(len(key)<512):
            key='0'+key
        print("\nDerived key:", key)
        time.sleep(0.5)
        mpk=key[:256]
        chaincode=key[256:]
        print("\nMaster private key",mpk)
        print("\nChain code",chaincode)
        time.sleep(1)
        #Extraire la master public key
        
        mpk2=hex(int(mpk,2))
        mpk2 = codecs.decode(mpk2[2:], 'hex')
        public_key_raw = ecdsa.SigningKey.from_string(mpk2, curve=ecdsa.SECP256k1).verifying_key
        public_key_bytes = public_key_raw.to_string()
        
        public_key_hex = codecs.encode(public_key_bytes, 'hex')
        print("\nMaster public key",public_key_hex)
        public_key=bin(int(public_key_hex,16))[2:]
        print("\nMaster public key",public_key)
        time.sleep(1)
        #Générer une clé enfant
        #Générer une clé enfant à l’index N
        
        print("Entrez l'index des enfants clés voulu")
        index=input()
        index=bin(int(index))
        while(len(index)<32):
            index='0'+index
        prehash_child=public_key+chaincode+index
        hashed=hashlib.sha256(prehash_child.encode('utf-8')).hexdigest()
        salt_3=binascii.unhexlify(hashed)
        child_code = pbkdf2_hmac("sha512", password, salt_3, 2048, 64)
        child_code=binascii.hexlify(child_code)
        child_code=bin(int(child_code,16))[2:]
        while(len(child_code)<512):
            child_code='0'+child_code

        child_private_key=child_code[:256]
        child_chaincode=child_code[256:]
        print("\nChild private key",child_private_key)
        time.sleep(1)
        child_private_key2=hex(int(child_private_key,2))
        child_private_key2 = codecs.decode(child_private_key2[2:], 'hex')
        public_key_raw = ecdsa.SigningKey.from_string(child_private_key2, curve=ecdsa.SECP256k1).verifying_key
        public_key_bytes = public_key_raw.to_string() 
        public_key_hex = codecs.encode(public_key_bytes, 'hex')
        pub_key=bin(int(public_key_hex,16))[2:]
        
        
        #Générer une clé enfant à l’index N au niveau de dérivation M
        print("Entrez le niveau de dérivation voulu")
        deriv=int(input())
        
        child_M_key=Derivation(child_private_key,pub_key,child_chaincode,index,deriv)
        print("\nClé privée Enfant Niveau de dérivation M :",child_M_key)
            
    #%%  
        
        
    else:
        print("Numéro de question non valide, réessayez ou entrez exit")
    choice=input()
exit()

