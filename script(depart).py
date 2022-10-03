# -*- coding: utf-8 -*-

# penser à mettre sous forme de def et simplifier"

import secrets
import hashlib
from textwrap import wrap

#%%
# ici def (generer seed) : 

random_number=secrets.randbits(130);
binary_random_number=bin(random_number);


while(len(binary_random_number)!=130):
    random_number=secrets.randbits(130);
    binary_random_number=bin(random_number);
    
print(random_number)
binary_random_number=binary_random_number[2:]
print(binary_random_number)
print(len(binary_random_number))

#%%

hash_rdm_nbr=hashlib.sha256(binary_random_number.encode('utf-8')).hexdigest()
hash_rdm_nbr=bin(int(hash_rdm_nbr,16))[2:]
print(hash_rdm_nbr)

#%%

entropy=binary_random_number+hash_rdm_nbr[0:4]
print(entropy)
print(len(entropy))
#%% separation en 12 mots seed

tab=wrap(entropy, 11)
print(tab)

#%%
f=open(r'word.txt','r')
liste_mots=f.readlines()
tab_mots=[]
for x in tab:
    x=int(x,2)
    print(x,liste_mots[x-1])
    tab_mots.append(liste_mots[x-1].strip("\n"))
    
print(tab_mots)

#%%

# Faire le reverse pour la fin de l'exo 

#%%

# 2 ème partie 



