

## DSS FORK : Digital Signature Service with Quantum Safe Hybrid Certificates

This is a fork of the official repository for project DSS : https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/Digital+Signature+Service+-++DSS. The DSS project provides a digital signature service to sign and validate digital signatures on different types of files. In this fork we have mainly look at the PAdES functionality. PAdES is a standard to sign and validate pdf documents. In the official repository several types of certificates and cryptographic algorithms are supported. We have extended the functionality with quantum safe hybrid certificates.

This work has been performed under the [Hapkido project](https://hapkido.tno.nl/). The Hybrid Approach for quantum-safe Public Key Infrastructure Development for Organisations (HAPKIDO) project is a five-year initiative that aims to develop a roadmap for the transition to quantum-safe Public Key Infrastructures (PKIs).


## Hybrid certificates
Hybrid certificates apply multiple cryptographic algorithms during signing. By using multiple algorithms when signing a document enables the verifier to check one of the signatures to check the validity. If one of the algorithms is broken or bugged the other algoirthm can still be used to validate the signature. 

In the light of the quantum computer arriving within the next 30-ish years the advantage is being able to use a classical algorithm and a post-quantum secure algorithm. Allowing backwards compatibility to the user that have not migrated to post-quantum secure algorithms, while also supporting the people that have transitioned. Being able to support post-quantum secure algorithms and classical algorithms prolongs the validaty of PDF documents. 

In the fork we have added functionality for a hybrid certificate. The hybrid certificate adheres to [X.509 ITU-T](https://www.itu.int/rec/T-REC-X.509-201910-I) (the catalyst approach). The current implementation supports a hybrid certificate with any classical algorithm and FALCON-512 (provided by bouncy castle). Support for other algorithms can be extended by loading other encryption algorithms from the bounce castle framework.


____

The remainder of the README is from the original repository and left in, since the build and install steps are still the same.


# Requirements

The latest version of DSS framework has the following minimal requirements:

 * Java 11 and higher (tested up to Java 18) for the build is required. For usage Java 8 is a minimum requirement;
 * Maven 3.6 and higher;
 * Memory and Disk: see minimal requirements for the used JVM. In general the higher available is better;
 * Operating system: no specific requirements (tested on Windows and Linux).

# Maven repository

The release is published on Maven Central repository : 

https://central.sonatype.dev/namespace/eu.europa.ec.joinup.sd-dss

<pre>
&lt;!-- Add dss-bom for easy integration --&gt;
&lt;dependencyManagement&gt;
    &lt;dependencies&gt;
        &lt;dependency&gt;
            &lt;groupId&gt;eu.europa.ec.joinup.sd-dss&lt;/groupId&gt;
            &lt;artifactId&gt;dss-bom&lt;/artifactId&gt;
            &lt;version&gt;5.12.RC1&lt;/version&gt;
            &lt;type&gt;pom&lt;/type&gt;
            &lt;scope&gt;import&lt;/scope&gt;
        &lt;/dependency&gt;
    &lt;/dependencies&gt;
&lt;/dependencyManagement&gt;

&lt;!-- Add required modules (example) --&gt;
&lt;dependencies&gt;
    &lt;dependency&gt;
        &lt;groupId&gt;eu.europa.ec.joinup.sd-dss&lt;/groupId&gt;
        &lt;artifactId&gt;dss-utils-apache-commons&lt;/artifactId&gt;
    &lt;/dependency&gt;
    &lt;dependency&gt;
        &lt;groupId&gt;eu.europa.ec.joinup.sd-dss&lt;/groupId&gt;
        &lt;artifactId&gt;dss-xades&lt;/artifactId&gt;
    &lt;/dependency&gt;
    ...
&lt;/dependencies&gt;
</pre>

# Build and usage

A simple build of the DSS Maven project can be done with the following command:

```
mvn clean install
```

This installation will run all unit tests present in the modules, which can take more than one hour to do the complete build.

In addition to the general build, the framework provides a list of custom profiles, allowing a customized behavior:

 * quick - disables unit tests and java-doc validation, in order to process the build as quick as possible (takes 1-2 minutes). This profile cannot be used for a primary DSS build (see below).
 * quick-init - is similar to the `quick` profile. Disables java-doc validation for all modules and unit tests excluding some modules which have dependencies on their test classes. Can be used for the primary build of DSS.
 * slow-tests - executes all tests, including time-consuming unit tests.
 * owasp - runs validation of the project and using dependencies according to the [National Vulnerability Database (NVD)](https://nvd.nist.gov).
 * jdk19-plus - executed automatically for JDK version 9 and higher. Provides a support of JDK 8 with newer versions.
 * spotless - used to add a licence header into project files.
 
In order to run a build with a specific profile, the following command must be executed:

```
mvn clean install -P *profile_name*
```

# Documentation

The [documentation](dss-cookbook/src/main/asciidoc/dss-documentation.adoc) and samples are available in the dss-cookbook module. [SoapUI project](dss-cookbook/src/main/soapui) and [Postman project](dss-cookbook/src/main/postman) are also provided to illustrate SOAP/REST calls.

In order to build the documentation by yourself, the following command must be executed in *dss-cookbook* module:

```
mvn clean install -P asciidoctor
```

# JavaDoc

The JavaDoc is available on https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/apidocs/index.html

# Demonstration

The release is deployed on https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo

The source code of the demonstrations is available on https://github.com/esig/dss-demonstrations

# Ready-to-use bundles

Bundles which contain the above demonstration can be downloaded from the [Maven repository](https://ec.europa.eu/digital-building-blocks/artifact/service/rest/repository/browse/esignaturedss/eu/europa/ec/joinup/sd-dss/dss-demo-bundle/).

The code of the demonstration can be found on https://ec.europa.eu/digital-building-blocks/code/projects/ESIG/repos/dss-demos/browse

# Licenses

The DSS project is delivered under the terms of the Lesser General Public License (LPGL), version 2.1 [![License (LGPL version 2.1)](https://img.shields.io/badge/license-GNU%20LGPL%20version%202.1-blue.svg?style=flat-square)](https://opensource.org/licenses/LGPL-2.1)

SPDX-License-Identifier : LGPL-2.1
