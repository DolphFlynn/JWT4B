package app.controllers;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import gui.JWTInterceptTab;
import model.CustomJWToken;

public class ReadableTokenFormat {

  private static final String newline = System.getProperty("line.separator");
  private static final String titleHeaders = "Headers = ";
  private static final String titlePayload = newline + newline + "Payload = ";
  private static final String titleSignature = newline + newline + "Signature = ";

  public static String getReadableFormat(CustomJWToken token) {

    return titleHeaders + jsonBeautify(token.getHeaderJson()) + titlePayload + jsonBeautify(token.getPayloadJson())
        + titleSignature + "\"" + token.getSignature() + "\"";
  }

  public static CustomJWToken getTokenFromReadableFormat(String token) throws InvalidTokenFormat {
    if (!token.startsWith(titleHeaders)) {
      throw new InvalidTokenFormat("Cannot parse token");
    }

    token = token.substring(titleHeaders.length());

    if (!token.contains(titlePayload)) {
      throw new InvalidTokenFormat("Cannot parse token");
    }

    String[] split = token.split(titlePayload);

    String header = split[0];
    String payloadAndSignature = split[1];

    if (!payloadAndSignature.contains(titleSignature)) {
      throw new InvalidTokenFormat("Cannot parse token");
    }

    String[] split2 = payloadAndSignature.split(titleSignature);

    String payload = split2[0];
    String signature = split2[1];

    return new CustomJWToken(header, payload, signature);
  }

  public static String jsonBeautify(String input) {
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    JsonElement je = JsonParser.parseString(input);
    return gson.toJson(je);
  }

  public static CustomJWToken getTokenFromView(JWTInterceptTab jwtST) {
    String header = jwtST.getJwtHeaderArea().getText();
    String payload = jwtST.getJwtPayloadArea().getText();
    String signature = jwtST.getJwtSignatureArea().getText();
    return new CustomJWToken(header, payload, signature);
  }

  public static class InvalidTokenFormat extends Exception {

    private static final long serialVersionUID = 1L;

    public InvalidTokenFormat(String message) {
      super(message);
    }
  }
}