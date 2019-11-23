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
All the services communicating should know one key which is used to generate Hash using HMAC algorithm. 
Little background about HMAC, because hashes doesn't depend on key so rainbow table attacks are possible 
so people though of following possibilities :
1. Key || Message and then Hashing.
2. Message || Key and then Hashing.
issue with first approach, say we are getting hash for Karan( say block size of Hash Function is 5) as adjandskajd, 
now if we want to compute the hash for Karanpreet, i don't need key, i only need the hash of Karan. Why ?
because Hash functions works as a state machine and if i configure state to hash of Karan then preet, 
it will account preet too.
issue with second approach, say i know the collision in Hash of 2 message then same collision will exist in MAC too.

So HMAC is something like Hash(Key || Hash (Key || Message)) 
```

### Some of the Attacks against JWT ###
1. *none hashing algorithm*: none hashing algorithm is used by the JWT in case the 
integrity of token is already verified. so incase an attacked sends none hashing algorithm 
and signature as empty, it might be an issue. this was a vulnerability in many encryption algorithms.
``` so solution is disallowing none hashing algorithm ```
2. *which verification algorithm RSA or HMAC*: General issue in verification of token is the structure of verification 
method which is 
``` verify(string token, string verificationKey) ```
now say server is expecting to verify the algorithm using RSA and say hacker has signed the token with Public key and set
the Algorithm as "HS" ie HMAC with SHA then while calling verify method, server will send token and Public Key but the library will think HS as the algorithm so it will think verificationKey as HMAC secrete key and will return it as a valid.
```So Solution is that Algorithms to accept algorithm too.```
but there can be a counter argument that if server is allowing multiple algorithms then how we can handle this usecase.
Solution is using `kid` header field.

Question is how kid is useful ?
kid identifies the Algorithm and Key both. 

so say hacker has encrypted with public key and sends the algorithm as "HS". Also somehow hacker found both the `kids` for HS and RS algorithm then he/she provides kid of HS but while decrypting algorithm will use kid to get the key and the key will not match. Similarly say kid is mentioned as of RS then algorithm will not match and RSA will not work because decryption will not work.

if we change above case little bit and send "RS" as algorithm and kid of RS then it will not work because of encryption issue due to Asymmetric nature. if kid of HS is provided then key will not match.

3. *Not storing JWT cookie as Secure and Http only.*
4. *Storing JWT in local storage/session storage* -> Difference between local storage/session storage and Cookie is cookie cannot be retrieved with Javascript if hardened with Http only flag but local storage and session storage is accessed to javascript causing XSS attacks to exploit it.







  
  
