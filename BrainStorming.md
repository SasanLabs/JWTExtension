# JWT #

JSON web token is a self contained token for securely transmitting data between 2 parties. The information can be trusted and verified as it is digitally signed using 
1. Symmetric way : HMAC 
2. or Asymmetric way : RSA or ECDSA

### Structure of JWT token ###
``` [Base64(HEADER)].[Base64(PAYLOAD)].[Base64(SIGNATURE)] ```

Eg. ``` eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ ```

#### Header ####
``` {
     "alg": "HS256",
     "typ": "JWT"
    } 
```
#### Payload ####
```
    {
     "sub": "1234567890",
     "name": "John Doe",
     "admin": true
    }
```
#### Signature ####
```
HMACSHA256( base64UrlEncode(header) + "." + base64UrlEncode(payload), KEY )
```

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
#### *Why we are encrypting the Hash not the entire token ?* ####
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
#### *none hashing algorithm*: ####
none hashing algorithm is used by the JWT in case the 
integrity of token is already verified. so incase an attacked sends none hashing algorithm 
and signature as empty, it might be an issue. this was a vulnerability in many encryption algorithms.
``` so solution is disallowing none hashing algorithm ```

#### *which verification algorithm RSA or HMAC*: ####
General issue in verification of token is the structure of verification 
method which is 
``` verify(string token, string verificationKey) ```
now say server is expecting to verify the algorithm using RSA and say hacker has signed the token with Public key and set
the Algorithm as "HS" ie HMAC with SHA then while calling verify method, server will send token and Public Key but the library will think HS as the algorithm so it will think verificationKey as HMAC secrete key and will return it as a valid.
```So Solution is that Algorithms to accept algorithm too.```
but there can be a counter argument that if server is allowing multiple algorithms then how we can handle this usecase.
Solution is using `kid` header field.

##### Question is how kid is useful ? #####
kid identifies the Algorithm and Key both. 

so say hacker has encrypted with public key and sends the algorithm as "HS". Also somehow hacker found both the `kids` for HS and RS algorithm then he/she provides kid of HS but while decrypting algorithm will use kid to get the key and the key will not match. Similarly say kid is mentioned as of RS then algorithm will not match and RSA will not work because decryption will not work.

if we change above case little bit and send "RS" as algorithm and kid of RS then it will not work because of encryption issue due to Asymmetric nature. if kid of HS is provided then key will not match.

#### *No way to revoke JWT token issued untill expiry* ####
JWT inherent behaviour is there is no way to revoke token before the expiry date so incase a user token is stealed there is not way to invalidate jwt token. so solution can be:

when a user logs out storing jwt token hash with revoked date in revoke table and this table has higher precedence over the expiry date.

#### *Information disclosure* ####
In case sensitive internal information is stored in token then it is an issue as JWT is more about integrity of token and less about secrecy of information. so if we need secrecy then we might need to encrypt the token again making it secret. AEAD can be used for this usecase.

little information about AEAD:
AEAD is used in case we need Authentication and Integrity both ie Secrecy and Integrity.
AEAD modes are:
1. ``` Encrypt then Mac ```, encrypt the plain text and append the Mac of encrypted data with it. Gives integrity of encrypted data as well as secrecy of plain text. Key used for both Mac and plain text should be different else someone can read the plain text by bruteforcing the Mac.

![alt text](https://github.com/SasanLabs/JWTExtension/blob/master/Authenticated_Encryption_EtM.png)

2. ``` Mac then Encrypt ```, compute Mac of plain text and then encrypt the Mac and send it. it doesn't give any integrity of encrypted data but plain text is having both secrecy and integrity.

![alt text](https://github.com/SasanLabs/JWTExtension/blob/master/Authenticated_Encryption_MtE.png)

3. ``` Mac and Encrypt ```, encrypt the plain text and also compute mac of plain text and append. it doesn't give any integrity of encrypted data.

![alt text](https://github.com/SasanLabs/JWTExtension/blob/master/Authenticated_Encryption_EaM.png)

```approach 1 is recommended approach.```

#### *Storing JWT in local storage/session storage or as a Cookie* #### 
Difference between local storage/session storage and Cookie is cookie cannot be retrieved by Javascript if hardened with Http only flag but local storage and session storage is accessed to javascript causing XSS attacks to exploit it. Plus local storage will remain even if browser is closed and but session storage goes away on closing browser.

so from above discussion you might think that cookie is the best place to store JWT but this is not exactly the case.
`Best practise is storing JWT in session storage` reason being is cookies are sent to each request causing it vulnerable to XSRF/CSRF even if they are hardened ie Http Only and Secure flags. Counter argument might be but Session storage is vulnerable to XSS which is also very dangerous.

##### Fingerprinting JWT token #####
so in JWT token a random string is stored and then that random string will be stored in ```hardened cookie``` so even if jwt is stolen user cannot fetch the cookie which contains random string. but if attacker steals the JWT, he/she can read the random string and set the cookie as random string, which can be a attack vector. so solution is storing MAC in JWT token and random string in cookie so that attacker even after stealing the JWT token cannot use it.

``` Note: however JWT token is stored in cookie can be very secure if XSRF/CSRF is properly handled.```

#### *Not storing JWT token or Fingerprint in cookie as Secure, Httponly, SameSite and Cookie Prefix*: ####
Secure and HttpOnly are the simple flags which need to be set for any cookie. they ensure that cookies are send to the request if send over HTTPS and only available to Http Protocol and not accessible to JavaScript respectively.

##### SameSite: #####
a way to restrict cross site sending of cookies. there are three modes of SameSite:
1. *Strict*, meaning say A.com set the cookies with Strict mode of SameSite and then user opened B.com then while navigating from B.com to A.com, will not send the cookie flagged as Strict.
2. *Lax*, meaning Say A.com set the cookies with Lax mode of SameSite then when user opened B.com and then Get requests which changes the Top URL of browser like ahref or links, browser will send the cookies with lax flag but if top level url doesn't change then it will not send the lax cookie like in case of Ajax calls or Image rendering. Also Lax flagged cookies will not be sent in case of CSRF prone methods like POST/PUT/DELETE
3. *None*, Send to A.com even while navigating from B.com

Default behavior of browsers had changed from None to Lax.

##### Cookie Prefix: #####
There are certain cases where a subdomain can read or overwrite the domain cookies ie say a subdomain A.B.com can overwrite B.com cookies. so in case a malicious subdomain or a subdomain having some issues can impact the cookie values.

`__Secure` cookie name prefix is used to allow overwriting of the cookies only if done over secure channel ie secure attribute is required.

`__Host-` cookie name prefix will not allow parent domains cookie overwriting and also requires secure channel ie it requires both Path and Secure attribute.

[More information](https://googlechrome.github.io/samples/cookie-prefixes/) 

#### *BruteForce attack* ####
Due to weak secret HMAC based JWT becomes vulnerable to bruteforce attacks and can be cracked using password dictionary attacks. Prevention could be choosing secret as a large strong (containing numeric and alpha numeric characters) string and then trying password dictionary attack with combined JWT to check the strength.

try using HashCat or JohnTheRipper for password dictionary attack.

[More Information](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html)



  
  
