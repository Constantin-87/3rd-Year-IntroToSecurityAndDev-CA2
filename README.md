# SecureChatApp

SecureChatApp is a web-based secure communication platform that uses end-to-end encryption to ensure that messages remain private and secure.

## Features

- End-to-end encryption using AES-GCM for symmetric encryption and RSA-OAEP for asymmetric encryption.
- Secure registration and authentication system for users.
- Real-time messaging capabilities.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- You have installed XAMPP which includes PHP, Apache Server, MySQL, and Tomcat.
- You have NetBeans IDE installed with Java EE support.
- You are using JDK 17 for development.
- You have Maven installed for dependency management and building the project.

## Installation

To install SecureChatApp, follow these steps:

1. Clone the repository to your local machine: git clone https://github.com/Constantin-87/SecureChatApp.git
 
2. Open the project in NetBeans IDE.

## Configuration

1. Start XAMPP and ensure that the MySQL and Tomcat services are running.

2. Create a new database for the application using the MySQL service in XAMPP.

3. Import the initial `securechatapp_database.sql` schema into your database via the phpMyAdmin interface or MySQL command line.

4. Configure the database connection settings in the `config.properties` file located within the `src/main/resources` directory of the project.

5. Ensure the project's JDK is set to JDK 17 in NetBeans IDE under `Tools > Java Platforms`.

6. Configure the project to use Java EE 7 by setting the Maven `pom.xml` dependency for `javaee-web-api` to version `7.0`.

## Tomcat Server Setup in NetBeans with XAMPP

1. In NetBeans, go to the "Services" tab, right-click on "Servers," and select "Add Server."

2. Choose "Apache Tomcat or TomEE" and provide the path to the Tomcat directory within your XAMPP installation.

3. Configure the following in the server settings:

- For HTTPS setup, locate the `server.xml` file in the `conf` directory of the Tomcat server within XAMPP and edit as follows:

  ```xml
  <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
             maxThreads="150" SSLEnabled="true">
    <UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol" />
    <SSLHostConfig>
      <Certificate certificateKeystoreFile="conf/securechat.keystore"
                   certificateKeystorePassword="Password"
                   certificateKeystoreType="PKCS12" />
    </SSLHostConfig>
  </Connector>
  
  <Connector port="8080" protocol="HTTP/1.1"
                   connectionTimeout="20000"
                   redirectPort="8443"
                   maxParameterCount="1000"/>  
  ```
- Replace `conf/securechat.keystore` with the path to your keystore file (the keystore password is: Password)
- Ensure the project is set to use the Tomcat server you've just configured in NetBeans.

## Running the Application

To run SecureChatApp using NetBeans and Tomcat, follow these steps:

1. Save any configuration files you have edited.

2. Build the project using Maven. In NetBeans, right-click on the project and select "Clean and Build."

3. Start the Tomcat server from within NetBeans IDE.

4. Deploy the application to the Tomcat server by selecting 'Run' in NetBeans.

5. Once the server starts, your web application should be accessible at: https://localhost:8443/SecureChatApp


6. Use the application through your web browser by registering a new user and logging in to chat securely.

## SSL/TLS Certificate Note

The SecureChatApp uses a self-signed SSL certificate for HTTPS connections. Because of this, web browsers will typically display a security warning when you first access the application.

To bypass the browser warning:

- For **Google Chrome**:
  - Click on "Advanced" and then click "Proceed to localhost (unsafe)".
  
- For **Mozilla Firefox**:
  - Click on "Advanced…" then click "Accept the Risk and Continue".

- For **Safari**:
  - Click on "Show Details", then click "visit this website" and "visit website" in the prompt.

- For **Microsoft Edge**:
  - Click on "Details" and then "Go on to the webpage (not recommended)".


## Contributing to SecureChatApp

To contribute to SecureChatApp, follow these steps:

1. Fork this repository.
2. Create a new branch for your modifications (`git checkout -b feature_branch`).
3. Make changes and test.
4. Commit your changes (`git commit -am 'Add some feature'`).
5. Push to the branch (`git push origin feature_branch`).
6. Create a new Pull Request.

