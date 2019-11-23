# JWT #

JSON web token is a self contained token for securely transmitting data between 2 parties. The information can be trusted and verified as it is digitally signed using 
1. Symmetric way : HMAC 
2. or Asymmetric way : RSA or ECDSA

## Usage of JWT ##

With the introduction of Microservices and also more emphasize on stateless applications JWT become very famous. Reason being
1. it helps achieving stateless ness as it is passed to User in Cookies and it has all the information which application needs and there is no need to store session related information at server side.
2. Also Say there are bunch of Microservices, if JWT is not there then each microservice need to talk to a central system to know if user is authorized to do any activity or to fetch ay user related information which might impact the performance of that single central system and also increases a lot of dependency on that system. plus latency which is introduced due to each service calling a central system.

## Implementation issues ##

Due to lack of knowledge 
