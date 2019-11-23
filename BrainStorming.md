# JWT #

JSON web token is a self contained token for securely transmitting data between 2 parties. The information can be trusted and verified as it is digitally signed using 
1. Symmetric way : HMAC 
2. or Asymmetric way : RSA or ECDSA

## Usage of JWT ##

With the introduction of Microservices and also more emphasize on stateless applications JWT become very famous. Reason being
1. it helps achieving stateless ness as it is passed to User in Cookies and it has all the information which application needs and there is no need to store session related information at server side.
2. Also Say there are bunch of Microservices, if JWT is not there then each microservice need to talk to a central system to know if user is authorized to do any activity or to fetch ay user related information which might impact the performance of that single central system and also increases a lot of dependency on that system. plus latency which is introduced due to each service calling a central system.

## Implementation details ##

Once a user logs in into the application, server provides the JWT token in the response header as a Set-Cookie. Now in each request to same service or to other services (Microservices) browser automatically sends cookies with the request.

### *How to ensures that someone has not tempered the JWT ?* ###
JWT tokens are digitally signed ie 
1. In case of Asymmetric Algorithm,
``` 
they are encrypted by the private key of the service which issues it, and as we know private key is 
only known to the service which has encrypted and someone with the public key of the service 
can easily verify that and if services/parties trust each other then this ensures that the issuer 
is authentic/trusted. Plus Asymmetric algorithm gives benefits of Non-Repudiation which is not there 
in Symmetric algorithm.
```
there is little tweak to what is explained above as we will not encrypt the entire token but instead encrypt the Hash of the token. 
### *Why we are encrypting the Hash not the entire token ?* ###
```
1.1. Asymmetric algorithms are slow so if token is large then it can have a performance impact.
1.2. Encryption algorithms doesn't provide integrity ie to know if something is modified. 
  1.2.1 Someone can modify one bit of encrypted data and decryption can be successful too.
```
2. HMAC based or Symmetric Key based Algorithm,
```
All the services communicating should know one key which is used to generate Hash using HMAC algorithm. Little background about HMAC, because hashes doesn't depend on key so rainbow table attacks are possible so people though of following possibilities :
1. Key || Message and then Hashing.
2. Message || Key and then Hashing.
issue with first approach, say we are getting hash for Karan( say block size of Hash Function is 5) as adjandskajd, now if we want to compute the hash for Karanpreet, i don't need key, i only need the hash of Karan. Why ? because Hash functions works as a state machine and if i configure state to hash of Karan then preet, it will account preet too.
issue with second approach, say i know the collision in Hash of 2 message then same collision will exist in MAC too.

So HMAC is something like Hash(Key || Hash (Key || Message)) 
```



  
  
