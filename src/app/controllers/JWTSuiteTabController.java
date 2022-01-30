package app.controllers;

import java.awt.Component;
import java.util.List;

import javax.swing.JTabbedPane;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import app.helpers.Output;
import burp.ITab;
import gui.JWTSuiteTab;
import model.CustomJWToken;
import model.JWTSuiteTabModel;
import model.Settings;
import model.TimeClaim;

import static app.controllers.VerificationData.verifyTokenWithKeyForAlgorithm;

// used to provide the standalone suite tab after "User Options"
public class JWTSuiteTabController implements ITab {

  private final JWTSuiteTabModel jwtSTM;
  private final JWTSuiteTab jwtST;

  public JWTSuiteTabController(final JWTSuiteTabModel jwtSTM, final JWTSuiteTab jwtST) {
    this.jwtSTM = jwtSTM;
    this.jwtST = jwtST;

    createAndRegisterActionListeners(jwtSTM, jwtST);
  }

  // This method was copied from
  // https://support.portswigger.net/customer/portal/questions/16743551-burp-extension-get-focus-on-tab-after-custom-menu-action
  public void selectJWTSuiteTab() {
    Component current = this.getUiComponent();
    do {
      current = current.getParent();
    } while (!(current instanceof JTabbedPane));

    JTabbedPane tabPane = (JTabbedPane) current;
    for (int i = 0; i < tabPane.getTabCount(); i++) {
      if (tabPane.getTitleAt(i).equals(this.getTabCaption()))
        tabPane.setSelectedIndex(i);
    }
  }

  public void contextActionSendJWTtoSuiteTab(String jwts, boolean fromContextMenu) {
    jwts = jwts.replace("Authorization:", "");
    jwts = jwts.replace("Bearer", "");
    jwts = jwts.replace("Set-Cookie: ", "");
    jwts = jwts.replace("Cookie: ", "");
    jwts = jwts.replaceAll("\\s", "");
    jwtSTM.setJwtInput(jwts);
    try {
      CustomJWToken jwt = new CustomJWToken(jwts);
      List<TimeClaim> tcl = jwt.getTimeClaimList();
      jwtSTM.setTimeClaims(tcl);
      jwtSTM.setJwtJSON(ReadableTokenFormat.getReadableFormat(jwt));
    } catch (Exception e) {
      Output.outputError("JWT Context Action: " + e.getMessage());
    }
    if (fromContextMenu) {
      // Reset View and Select
      jwtSTM.setJwtKey("");
      selectJWTSuiteTab();
    } else {
      // Since we changed the JWT, we need to check the Key/Signature too
      contextActionKey(jwtSTM.getJwtKey());
    }
    jwtST.updateSetView();
  }

  public void contextActionKey(String key) {
    CustomJWToken token = new CustomJWToken(jwtST.getJWTInput());
    VerificationData verificationData = verifyTokenWithKeyForAlgorithm(token.getToken(), key, token.getAlgorithm());

    jwtSTM.setJwtKey(key);
    jwtSTM.setJwtSignatureColor(verificationData.signatureColor);
    jwtSTM.setVerificationLabel(verificationData.verificationLabel);
    jwtSTM.setVerificationResult(verificationData.verificationResult);

    jwtST.updateSetView();
  }

  @Override
  public String getTabCaption() {
    return Settings.TAB_NAME;
  }

  @Override
  public Component getUiComponent() {
    return jwtST;
  }

  private void createAndRegisterActionListeners(final JWTSuiteTabModel jwtSTM, final JWTSuiteTab jwtST) {
    DocumentListener jwtDocInputListener = new DocumentListener() {

      @Override
      public void removeUpdate(DocumentEvent e) {
        jwtSTM.setJwtInput(jwtST.getJWTInput());
        contextActionSendJWTtoSuiteTab(jwtSTM.getJwtInput(), false);
      }

      @Override
      public void insertUpdate(DocumentEvent e) {
        jwtSTM.setJwtInput(jwtST.getJWTInput());
        contextActionSendJWTtoSuiteTab(jwtSTM.getJwtInput(), false);
      }

      @Override
      public void changedUpdate(DocumentEvent e) {
      }
    };
    DocumentListener jwtDocKeyListener = new DocumentListener() {

      @Override
      public void removeUpdate(DocumentEvent e) {
        jwtSTM.setJwtKey(jwtST.getKeyInput());
        contextActionKey(jwtSTM.getJwtKey());
      }

      @Override
      public void insertUpdate(DocumentEvent e) {
        jwtSTM.setJwtKey(jwtST.getKeyInput());
        contextActionKey(jwtSTM.getJwtKey());
      }

      @Override
      public void changedUpdate(DocumentEvent e) {
      }
    };

    jwtST.registerDocumentListener(jwtDocInputListener, jwtDocKeyListener);
  }
}
