package com.bolt12pay.companion;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;

import org.json.JSONObject;
import org.unifiedpush.android.connector.FailedReason;
import org.unifiedpush.android.connector.PushService;
import org.unifiedpush.android.connector.data.PushEndpoint;
import org.unifiedpush.android.connector.data.PushMessage;

import java.nio.charset.StandardCharsets;
import java.text.NumberFormat;

public final class PushServiceImpl extends PushService {
    private static final String CHANNEL_ID = "incoming_payments";

    @Override
    public void onNewEndpoint(PushEndpoint endpoint, String instance) {
        PushApi.syncSubscription(this, endpoint);
    }

    @Override
    public void onMessage(PushMessage message, String instance) {
        if (!message.getDecrypted()) {
            new PushSettings(this).setLastError(getString(R.string.push_encryption_failed));
            return;
        }
        try {
            JSONObject payload =
                    new JSONObject(new String(message.getContent(), StandardCharsets.UTF_8));
            if (payload.optInt("version") != 1
                    || !"payment_received".equals(payload.optString("type"))) {
                return;
            }
            String eventId = payload.optString("event_id");
            PushSettings settings = new PushSettings(this);
            if (!settings.rememberEvent(eventId)) return;
            showPaymentNotification(
                    eventId,
                    Math.max(0, payload.optLong("amount_sat")),
                    payload.optString("method", "lightning"),
                    payload.optString("payment_type", "payment"));
        } catch (Exception error) {
            new PushSettings(this).setLastError(getString(R.string.push_message_invalid));
        }
    }

    @Override
    public void onUnregistered(String instance) {
        new PushSettings(this).setLastError(getString(R.string.push_unregistered));
    }

    @Override
    public void onRegistrationFailed(FailedReason reason, String instance) {
        new PushSettings(this).setLastError(
                getString(R.string.push_registration_failed_detail, reason.toString()));
    }

    private void showPaymentNotification(
            String eventId,
            long amountSat,
            String method,
            String paymentType) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        NotificationChannel channel =
                new NotificationChannel(
                        CHANNEL_ID,
                        getString(R.string.push_channel_name),
                        NotificationManager.IMPORTANCE_HIGH);
        channel.setDescription(getString(R.string.push_channel_description));
        channel.enableVibration(true);
        channel.setLightColor(Color.rgb(247, 147, 26));
        channel.enableLights(true);
        channel.setLockscreenVisibility(Notification.VISIBILITY_PRIVATE);
        manager.createNotificationChannel(channel);

        String amount = NumberFormat.getIntegerInstance().format(amountSat);
        String title = getString(R.string.push_payment_received_title, amount);
        String body = describePayment(method, paymentType);
        String serverUrl = new ServerSettings(this).load();
        Intent open =
                new Intent(
                        Intent.ACTION_VIEW,
                        Uri.parse((serverUrl == null ? "https://localhost" : serverUrl) + "/pay"));
        PendingIntent pendingIntent =
                PendingIntent.getActivity(
                        this,
                        eventId.hashCode(),
                        open,
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification publicVersion =
                new Notification.Builder(this, CHANNEL_ID)
                        .setSmallIcon(R.drawable.ic_notification_bolt)
                        .setContentTitle(getString(R.string.push_private_title))
                        .setContentText(getString(R.string.push_private_body))
                        .build();
        Notification notification =
                new Notification.Builder(this, CHANNEL_ID)
                        .setSmallIcon(R.drawable.ic_notification_bolt)
                        .setContentTitle(title)
                        .setContentText(body)
                        .setAutoCancel(true)
                        .setCategory(Notification.CATEGORY_STATUS)
                        .setVisibility(Notification.VISIBILITY_PRIVATE)
                        .setPublicVersion(publicVersion)
                        .setContentIntent(pendingIntent)
                        .build();
        manager.notify(eventId.hashCode(), notification);
    }

    private String describePayment(String method, String paymentType) {
        if ("zap".equals(method) || "zap".equals(paymentType)) {
            return getString(R.string.push_method_zap);
        }
        if ("bolt12".equals(method) || "offer".equals(paymentType)) {
            return getString(R.string.push_method_bolt12);
        }
        if ("lightning_address".equals(method) || "lnurl".equals(method)) {
            return getString(R.string.push_method_lightning_address);
        }
        if ("keysend".equals(method)) {
            return getString(R.string.push_method_keysend);
        }
        return getString(R.string.push_method_lightning);
    }
}
