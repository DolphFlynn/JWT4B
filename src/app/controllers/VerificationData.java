package app.controllers;

import app.algorithm.AlgorithmLinker;
import app.helpers.Output;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import model.Settings;
import model.Strings;

import java.awt.*;
import java.io.UnsupportedEncodingException;

class VerificationData {
    final Color signatureColor;
    final String verificationLabel;
    final String verificationResult;

    VerificationData(Color signatureColor, String verificationLabel, String verificationResult) {
        this.signatureColor = signatureColor;
        this.verificationLabel = verificationLabel;
        this.verificationResult = verificationResult;
    }

    static VerificationData verifyTokenWithKeyForAlgorithm(String token, String key, String algorithm) {
      try {
        JWTVerifier verifier = JWT.require(AlgorithmLinker.getVerifierAlgorithm(algorithm, key)).build();
        DecodedJWT test = verifier.verify(token);
        test.getAlgorithm();
        return new VerificationData(Settings.COLOR_VALID, Strings.verificationValid, "");
      } catch (JWTVerificationException | IllegalArgumentException | UnsupportedEncodingException e) {
        String verificationResult = e.getMessage();
        Output.output("Verification failed (" + verificationResult + ")");

        if (e instanceof SignatureVerificationException) {
          return new VerificationData(Settings.COLOR_INVALID, Strings.verificationInvalidSignature, verificationResult);
        } else if (e instanceof InvalidClaimException) {
          return new VerificationData(Settings.COLOR_PROBLEM_INVALID, Strings.verificationInvalidClaim, verificationResult);
        } else if (e instanceof JWTVerificationException) {
          return new VerificationData(Settings.COLOR_PROBLEM_INVALID, Strings.verificationError, verificationResult);
        } else {
          return new VerificationData(Settings.COLOR_PROBLEM_INVALID, Strings.verificationInvalidKey, verificationResult);
        }
      }
    }
}
