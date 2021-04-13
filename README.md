# RSAKeys
[![Java CI with Maven](https://github.com/MCTzOCK/RSAKeys/actions/workflows/maven.yml/badge.svg)](https://github.com/MCTzOCK/RSAKeys/actions/workflows/maven.yml)

## Installation

Add this to your pom.xml and run ``mvn install``

```xml
<dependency>
  <groupId>de.mctzock</groupId>
  <artifactId>keys</artifactId>
  <version>1.0-SNAPSHOT</version>
  <scope>compile</scope>
</dependency>
```

## Example

```java
package org.example.examplepackage;

import de.mctzock.keys.RSAKeys;

import java.security.KeyPair;

public class Main {
  
  public static void main(String[] args) {
    // generate key pair
    KeyPair keyPair = RSAKeys.gen(2048); // size of keys
    
    // encrypt message
    byte[] encrypted = RSAKeys.encrypt("Hello World!", keyPair.getPublic());
    
    // decrypt message
    String decrypted = RSAKeys.decrypt(encrypted, keyPair.getPrivate());
    
    // For more (e.g. reading keys from file) please view the java docs
  }
}

## Java Docs
The JavaDocs can be found [here](https://mctzock.github.io/RSAKeys/)
```
