var SUBMIT_URL = "https://upwind-home-ass.onrender.com/api/v1/analyze";
var RESULT_BASE_URL = "https://upwind-home-ass.onrender.com/api/v1/result/";

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

  // Client-side cleanup before leaving the browser
  var cleanHtml = removeTrackingPixels(bodyHtml);
  var urls      = extractUrls(cleanHtml || bodyText).map(stripUrlPii);
  var cleanBody = stripPii(bodyText || "");
  var cleanSubject = stripPii(message.getSubject());

  var attachments = message.getAttachments().map(function(a) {
    var entry = { name: a.getName(), mime_type: a.getContentType() };
    try {
      // Only hash files under 5MB to avoid timeout
      if (a.getSize() <= 5 * 1024 * 1024) {
        var bytes = a.getBytes();
        var hashBytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
        entry.sha256 = hashBytes.map(function(b) {
          return ("0" + (b & 0xFF).toString(16)).slice(-2);
        }).join("");
      }
    } catch (e) {}
    return entry;
  });

  return {
    message_id: messageId,
    subject: cleanSubject,
    headers: {
      spf: spf,
      dkim: dkim,
      dmarc: dmarc,
      from_address: message.getFrom(),
      reply_to: rawHeaders["reply-to"] || null,
      received_from: rawHeaders["received"] || null,
    },
    body_html: cleanHtml,
    body_text: cleanBody,
    urls: urls,
    attachments: attachments,
  };
}

var HEALTH_URL = "https://upwind-home-ass.onrender.com/health";
var POLL_INTERVAL_MS = 3000;
var POLL_MAX_ATTEMPTS = 40; // up to ~2 minutes

function callBackend(payload) {
  // Warm up the server
  try {
    UrlFetchApp.fetch(HEALTH_URL, { muteHttpExceptions: true });
  } catch (e) {}

  // Submit the task
  var submitResponse = UrlFetchApp.fetch(SUBMIT_URL, {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
  });

  if (submitResponse.getResponseCode() !== 200) {
    throw new Error("Submit failed: HTTP " + submitResponse.getResponseCode());
  }

  var taskId = JSON.parse(submitResponse.getContentText()).task_id;

  // Poll until ready
  for (var i = 0; i < POLL_MAX_ATTEMPTS; i++) {
    Utilities.sleep(POLL_INTERVAL_MS);

    var pollResponse = UrlFetchApp.fetch(RESULT_BASE_URL + taskId, {
      method: "get",
      muteHttpExceptions: true,
    });

    if (pollResponse.getResponseCode() !== 200) continue;

    var body = JSON.parse(pollResponse.getContentText());
    if (body.status === "ready") return body.result;
    if (body.status === "error") throw new Error("Analysis failed on worker");
    // status === "pending" → keep polling
  }

  throw new Error("Timed out waiting for analysis result");
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
  return [...new Set(matches)].slice(0, 30);
}

function stripPii(text) {
  if (!text) return "";
  // Credit cards
  text = text.replace(/\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/g, "[CREDIT_CARD]");
  // SSN
  text = text.replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[SSN]");
  // Phone numbers
  text = text.replace(/\b(\+?1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b/g, "[PHONE_NUMBER]");
  // Israeli phone numbers
  text = text.replace(/\b0[5-9]\d[\-\s]?\d{7}\b/g, "[PHONE_NUMBER]");
  // Israeli ID (9 digits)
  text = text.replace(/\b\d{9}\b/g, "[ID_NUMBER]");
  // Street addresses
  text = text.replace(/\b\d{1,5}\s+[A-Za-z\s]{3,30}(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b/gi, "[PHYSICAL_ADDRESS]");
  return text;
}

function removeTrackingPixels(html) {
  if (!html) return "";
  // Remove 1x1 pixel images used for tracking
  return html.replace(/<img[^>]*(width=["']?1["']?|height=["']?1["']?)[^>]*\/?>/gi, "");
}

function stripUrlPii(url) {
  // Redact common PII query parameters from tracking URLs
  return url.replace(/([?&])(email|mail|user|name|fname|lname|first_name|last_name|recipient|uid|userid|user_id|contact)=([^&]*)/gi, "$1$2=[REDACTED]");
}
