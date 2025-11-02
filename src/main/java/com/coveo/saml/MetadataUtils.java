package com.coveo.saml;

import java.io.StringWriter;
import java.security.cert.X509Certificate;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MetadataUtils {

  private static final Logger logger = LoggerFactory.getLogger(SamlClient.class);

  public static String generateSpMetadata(String entityId, String assertionConsumerServiceURL) {
    return generateSpMetadata(entityId, assertionConsumerServiceURL, null);
  }

  public static String generateSpMetadata(
      String entityId, String assertionConsumerServiceURL, X509Certificate certificate) {
    try {
      InitializationService.initialize();

      var spEntityDescriptor = createSAMLObject(EntityDescriptor.class);
      if (spEntityDescriptor == null) {
        return null;
      }
      spEntityDescriptor.setEntityID(entityId);
      var spSSODescriptor = createSAMLObject(SPSSODescriptor.class);
      if (spSSODescriptor == null) {
        return null;
      }

      spSSODescriptor.setWantAssertionsSigned(false);
      spSSODescriptor.setAuthnRequestsSigned(false);

      if (certificate != null) {

        spSSODescriptor.setWantAssertionsSigned(true);
        spSSODescriptor.setAuthnRequestsSigned(true);

        var keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        var keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        var encKeyDescriptor = createSAMLObject(KeyDescriptor.class);
        if (encKeyDescriptor == null) {
          return null;
        }

        encKeyDescriptor.setUse(UsageType.ENCRYPTION);

        Credential credential = new BasicX509Credential(certificate);

        try {
          encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(credential));
        } catch (Exception e) {
          logger.error("Error while creating credentials", e);
        }
        spSSODescriptor.getKeyDescriptors().add(encKeyDescriptor);

        var signKeyDescriptor = createSAMLObject(KeyDescriptor.class);
        if (signKeyDescriptor == null) {
          return null;
        }

        signKeyDescriptor.setUse(UsageType.SIGNING); // Set usage

        try {
          signKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(credential));
        } catch (SecurityException e) {
          logger.error("Error while creating credentials", e);
        }
        spSSODescriptor.getKeyDescriptors().add(signKeyDescriptor);
      }

      var nameIDFormat = createSAMLObject(NameIDFormat.class);
      if (nameIDFormat == null) {
        return null;
      }

      nameIDFormat.setURI("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
      spSSODescriptor.getNameIDFormats().add(nameIDFormat);

      var assertionConsumerService = createSAMLObject(AssertionConsumerService.class);
      if (assertionConsumerService == null) {
        return null;
      }
      assertionConsumerService.setIndex(1);
      assertionConsumerService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);

      assertionConsumerService.setLocation(assertionConsumerServiceURL);
      spSSODescriptor.getAssertionConsumerServices().add(assertionConsumerService);

      spSSODescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

      spEntityDescriptor.getRoleDescriptors().add(spSSODescriptor);

      DocumentBuilder builder;
      var factory = DocumentBuilderFactory.newInstance();
      factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

      builder = factory.newDocumentBuilder();
      var document = builder.newDocument();
      var out =
          XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(spEntityDescriptor);
      out.marshall(spEntityDescriptor, document);

      var transformerfactory = TransformerFactory.newInstance();
      transformerfactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
      var transformer = transformerfactory.newTransformer();
      var stringWriter = new StringWriter();
      var streamResult = new StreamResult(stringWriter);
      var source = new DOMSource(document);
      transformer.setOutputProperty(OutputKeys.INDENT, "yes");
      transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
      transformer.transform(source, streamResult);
      stringWriter.close();

      return stringWriter.toString();
    } catch (Exception e) {
      logger.error("Error while generation SP metadata", e);
      return null;
    }
  }

  public static <T> T createSAMLObject(final Class<T> clazz) {
    var builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

    QName defaultElementName = null;
    try {
      defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
    } catch (Exception e) {
      logger.error("Error while creating SAML object", e);
      return null;
    }
    var object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);

    return object;
  }
}
