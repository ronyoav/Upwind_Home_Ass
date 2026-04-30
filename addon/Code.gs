var BACKEND_URL = "https://upwind-home-ass.onrender.com/api/v1/analyze";

function onGmailMessage(e) {
  var accessToken = e.messageMetadata.accessToken;
  var messageId = e.messageMetadata.messageId;
  GmailApp.setCurrentMessageAccessToken(accessToken);

  var message = GmailApp.getMessageById(messageId);
  var payload = buildPayload(message, messageId);

  try {
    var result = callBackend(payload);
    return buildCard(result);
  } catch (err) {
    return buildErrorCard(err.message);
  }
}

function buildPayload(message, messageId) {
  var rawHeaders = {};
  try {
    var fullMessage = Gmail.Users.Messages.get("me", messageId, { format: "metadata", metadataHeaders: ["Authentication-Results", "Received", "Reply-To", "From", "Return-Path"] });
    fullMessage.payload.headers.forEach(function(h) {
      rawHeaders[h.name.toLowerCase()] = h.value;
    });
  } catch (e) {}

  var authResults = rawHeaders["authentication-results"] || "";
  var spf    = extractAuthValue(authResults, "spf");
  var dkim   = extractAuthValue(authResults, "dkim");
  var dmarc  = extractAuthValue(authResults, "dmarc");

  var bodyHtml = message.getBody();
  var bodyText = message.getPlainBody();
  var urls     = extractUrls(bodyHtml || bodyText);

  var attachments = message.getAttachments().map(function(a) {
    return { name: a.getName(), mime_type: a.getContentType() };
  });

  return {
    message_id: messageId,
    subject: message.getSubject(),
    headers: {
      spf: spf,
      dkim: dkim,
      dmarc: dmarc,
      from_address: message.getFrom(),
      reply_to: rawHeaders["reply-to"] || null,
      received_from: rawHeaders["received"] || null,
    },
    body_html: bodyHtml,
    body_text: bodyText,
    urls: urls,
    attachments: attachments,
  };
}

function callBackend(payload) {
  var options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
  };

  var response = UrlFetchApp.fetch(BACKEND_URL, options);
  var code = response.getResponseCode();

  if (code !== 200) {
    throw new Error("Backend returned HTTP " + code);
  }

  return JSON.parse(response.getContentText());
}

function extractAuthValue(authResults, protocol) {
  var re = new RegExp(protocol + "=([\\w]+)", "i");
  var match = authResults.match(re);
  return match ? match[1].toLowerCase() : null;
}

function extractUrls(text) {
  if (!text) return [];
  var re = /https?:\/\/[^\s"'<>]+/gi;
  var matches = text.match(re) || [];
  // Deduplicate and limit to 30
  return [...new Set(matches)].slice(0, 30);
}
