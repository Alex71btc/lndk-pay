package com.bolt12pay.companion;

import android.Manifest;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import org.unifiedpush.android.connector.UnifiedPush;

import static org.unifiedpush.android.connector.ConstantsKt.INSTANCE_DEFAULT;

public final class MainActivity extends Activity {
    private static final int NOTIFICATION_PERMISSION_REQUEST = 71;
    private ServerSettings serverSettings;
    private PushSettings pushSettings;
    private String pendingTarget;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        serverSettings = new ServerSettings(this);
        pushSettings = new PushSettings(this);
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        PairingLink pairingLink =
                intent == null || intent.getData() == null
                        ? null
                        : PairingLink.parse(intent.getData().toString());
        if (pairingLink != null) {
            if (!serverSettings.save(pairingLink.serverUrl)) {
                showMessageScreen(
                        getString(R.string.push_pairing_failed_title),
                        getString(R.string.server_save_error));
                return;
            }
            pushSettings.savePending(
                    pairingLink.pairingToken,
                    pairingLink.vapidPublicKey,
                    Build.MANUFACTURER + " " + Build.MODEL);
            beginPushRegistration();
            return;
        }

        pendingTarget = extractLightningTarget(intent);
        boolean isPaymentIntent =
                Intent.ACTION_VIEW.equals(intent.getAction())
                        && intent.getData() != null
                        && isSupportedScheme(intent.getData().getScheme());

        if (isPaymentIntent && pendingTarget == null) {
            showMessageScreen(
                    getString(R.string.invalid_link_title),
                    getString(R.string.invalid_link_message));
            return;
        }

        String serverUrl = serverSettings.load();
        if (pendingTarget != null && serverUrl != null) {
            openPaymentForm(serverUrl, pendingTarget);
            return;
        }

        showSettingsScreen(serverUrl == null ? "" : serverUrl);
        refreshExistingPushRegistration();
    }

    private void beginPushRegistration() {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                        != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                    new String[] {Manifest.permission.POST_NOTIFICATIONS},
                    NOTIFICATION_PERMISSION_REQUEST);
            return;
        }
        registerWithUnifiedPush();
    }

    @Override
    public void onRequestPermissionsResult(
            int requestCode,
            String[] permissions,
            int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != NOTIFICATION_PERMISSION_REQUEST) return;
        if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            registerWithUnifiedPush();
        } else {
            pushSettings.setLastError(getString(R.string.push_permission_denied));
            showMessageScreen(
                    getString(R.string.push_pairing_failed_title),
                    getString(R.string.push_permission_denied));
        }
    }

    private void registerWithUnifiedPush() {
        String vapid = pushSettings.vapidPublicKey();
        if (vapid.isEmpty()) {
            showMessageScreen(
                    getString(R.string.push_pairing_failed_title),
                    getString(R.string.push_pairing_link_invalid));
            return;
        }
        UnifiedPush.tryUseCurrentOrDefaultDistributor(
                this,
                success -> {
                    if (Boolean.TRUE.equals(success)) {
                        UnifiedPush.register(
                                this,
                                INSTANCE_DEFAULT,
                                getString(R.string.push_distributor_registration),
                                vapid);
                        showMessageScreen(
                                getString(R.string.push_pairing_started_title),
                                getString(R.string.push_pairing_started_message));
                    } else {
                        pushSettings.setLastError(getString(R.string.push_no_distributor));
                        showMessageScreen(
                                getString(R.string.push_pairing_failed_title),
                                getString(R.string.push_no_distributor));
                    }
                    return null;
                });
    }

    private void refreshExistingPushRegistration() {
        if (!pushSettings.isPaired() || pushSettings.vapidPublicKey().isEmpty()) return;
        try {
            UnifiedPush.register(
                    this,
                    INSTANCE_DEFAULT,
                    getString(R.string.push_distributor_registration),
                    pushSettings.vapidPublicKey());
        } catch (Exception error) {
            pushSettings.setLastError(getString(R.string.push_registration_failed));
        }
    }

    private String extractLightningTarget(Intent intent) {
        Uri data = intent == null ? null : intent.getData();
        return data == null ? null : LightningTarget.normalize(data.toString());
    }

    private boolean isSupportedScheme(String scheme) {
        return "lightning".equalsIgnoreCase(scheme) || "bitcoin".equalsIgnoreCase(scheme);
    }

    private void showSettingsScreen(String currentServerUrl) {
        int padding = dp(24);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(padding, padding, padding, padding);
        content.setBackgroundColor(Color.rgb(11, 18, 32));

        content.addView(logo(), centered(dp(112), dp(112), 0, dp(18)));

        TextView title = text(getString(R.string.setup_title), 28, Color.WHITE);
        title.setGravity(Gravity.CENTER);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        content.addView(title);

        TextView explanation =
                text(getString(R.string.setup_explanation), 16, Color.rgb(200, 208, 224));
        explanation.setGravity(Gravity.CENTER);
        explanation.setLineSpacing(0, 1.12f);
        explanation.setPadding(0, dp(12), 0, dp(18));
        content.addView(explanation);

        if (pendingTarget != null) {
            TextView pending =
                    text(getString(R.string.pending_payment), 15, Color.rgb(247, 147, 26));
            pending.setPadding(0, 0, 0, dp(16));
            content.addView(pending);
        }

        EditText serverInput = new EditText(this);
        serverInput.setHint(R.string.server_url_hint);
        serverInput.setText(currentServerUrl);
        serverInput.setSingleLine(true);
        serverInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        serverInput.setTextColor(Color.WHITE);
        serverInput.setHintTextColor(Color.rgb(150, 160, 180));
        serverInput.setBackgroundTintList(ColorStateList.valueOf(Color.rgb(247, 147, 26)));
        serverInput.setPadding(dp(12), 0, dp(12), 0);
        serverInput.setMinHeight(dp(52));
        content.addView(serverInput);

        TextView serverHelp =
                text(
                        getString(R.string.server_url_help),
                        13,
                        Color.rgb(170, 180, 198));
        serverHelp.setPadding(dp(12), dp(8), dp(12), 0);
        content.addView(serverHelp);

        Button saveButton = new Button(this);
        saveButton.setText(
                pendingTarget == null ? R.string.save_server : R.string.save_and_continue);
        saveButton.setTextColor(Color.rgb(11, 18, 32));
        saveButton.setTextSize(16);
        saveButton.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        saveButton.setMinHeight(dp(52));
        GradientDrawable buttonBackground = new GradientDrawable();
        buttonBackground.setColor(Color.rgb(247, 147, 26));
        buttonBackground.setCornerRadius(dp(14));
        saveButton.setBackground(buttonBackground);
        saveButton.setOnClickListener(
                ignored -> {
                    String normalized = ServerUrl.normalize(serverInput.getText().toString());
                    if (normalized == null) {
                        serverInput.setError(getString(R.string.server_url_error));
                        return;
                    }

                    if (!serverSettings.save(normalized)) {
                        serverInput.setError(getString(R.string.server_save_error));
                        return;
                    }
                    if (pendingTarget != null) {
                        openPaymentForm(normalized, pendingTarget);
                    } else {
                        Toast.makeText(this, R.string.server_saved, Toast.LENGTH_SHORT).show();
                        showSettingsScreen(normalized);
                    }
                });
        LinearLayout.LayoutParams buttonParams =
                new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT);
        buttonParams.topMargin = dp(16);
        content.addView(saveButton, buttonParams);

        TextView pushTitle = text(getString(R.string.push_settings_title), 20, Color.WHITE);
        pushTitle.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        pushTitle.setPadding(0, dp(28), 0, dp(8));
        content.addView(pushTitle);

        String pushStatus;
        int pushStatusColor;
        if (!pushSettings.lastError().isEmpty()) {
            pushStatus = getString(R.string.push_status_error, pushSettings.lastError());
            pushStatusColor = Color.rgb(255, 170, 120);
        } else if (pushSettings.isPaired()) {
            pushStatus = getString(R.string.push_status_enabled);
            pushStatusColor = Color.rgb(110, 220, 160);
        } else if (pushSettings.isPairing()) {
            pushStatus = getString(R.string.push_status_pairing);
            pushStatusColor = Color.rgb(247, 147, 26);
        } else {
            pushStatus = getString(R.string.push_status_disabled);
            pushStatusColor = Color.rgb(170, 180, 198);
        }
        TextView pushStatusView = text(pushStatus, 14, pushStatusColor);
        pushStatusView.setLineSpacing(0, 1.1f);
        content.addView(pushStatusView);

        TextView pushPrivacy = text(getString(R.string.push_privacy_note), 13, Color.rgb(170, 180, 198));
        pushPrivacy.setPadding(0, dp(8), 0, dp(8));
        content.addView(pushPrivacy);

        Switch commentToggle = new Switch(this);
        commentToggle.setText(R.string.push_show_comments);
        commentToggle.setTextColor(Color.WHITE);
        commentToggle.setTextSize(15);
        commentToggle.setChecked(pushSettings.showPaymentComments());
        commentToggle.setPadding(0, dp(6), 0, 0);
        commentToggle.setOnCheckedChangeListener(
                (button, checked) -> pushSettings.setShowPaymentComments(checked));
        content.addView(commentToggle);

        TextView commentPrivacy =
                text(
                        getString(R.string.push_show_comments_note),
                        13,
                        Color.rgb(170, 180, 198));
        commentPrivacy.setPadding(0, dp(4), 0, dp(12));
        content.addView(commentPrivacy);

        Button pushButton = new Button(this);
        pushButton.setText(
                pushSettings.isPaired()
                        ? R.string.push_disable
                        : pushSettings.isPairing()
                                ? R.string.push_retry
                                : R.string.push_open_setup);
        pushButton.setTextColor(Color.WHITE);
        pushButton.setTextSize(15);
        GradientDrawable pushButtonBackground = new GradientDrawable();
        pushButtonBackground.setColor(Color.rgb(40, 55, 78));
        pushButtonBackground.setCornerRadius(dp(14));
        pushButton.setBackground(pushButtonBackground);
        pushButton.setOnClickListener(
                ignored -> {
                    if (pushSettings.isPaired()) {
                        UnifiedPush.unregister(this, INSTANCE_DEFAULT);
                        PushApi.unregister(
                                this,
                                () -> {
                                    Toast.makeText(
                                                    this,
                                                    R.string.push_disabled,
                                                    Toast.LENGTH_SHORT)
                                            .show();
                                    showSettingsScreen(
                                            serverSettings.load() == null
                                                    ? ""
                                                    : serverSettings.load());
                                });
                    } else if (pushSettings.isPairing()) {
                        beginPushRegistration();
                    } else {
                        openNotificationSetup(currentServerUrl);
                    }
                });
        content.addView(pushButton);

        TextView safety = text(getString(R.string.safety_note), 14, Color.rgb(170, 180, 198));
        safety.setPadding(0, dp(18), 0, 0);
        content.addView(safety);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(content);
        setContentView(scroll);
    }

    private void showMessageScreen(String titleText, String messageText) {
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(24), dp(24), dp(24), dp(24));
        content.setBackgroundColor(Color.rgb(11, 18, 32));
        content.addView(logo(), centered(dp(112), dp(112), 0, dp(18)));
        TextView title = text(titleText, 28, Color.WHITE);
        title.setGravity(Gravity.CENTER);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        content.addView(title);

        TextView message = text(messageText, 16, Color.rgb(200, 208, 224));
        message.setPadding(0, dp(12), 0, 0);
        message.setGravity(Gravity.CENTER);
        message.setLineSpacing(0, 1.12f);
        content.addView(message);
        setContentView(content);
    }

    private void openNotificationSetup(String currentServerUrl) {
        String serverUrl = ServerUrl.normalize(currentServerUrl);
        if (serverUrl == null) {
            Toast.makeText(this, R.string.push_save_server_first, Toast.LENGTH_LONG).show();
            return;
        }
        Intent browserIntent =
                new Intent(Intent.ACTION_VIEW, Uri.parse(serverUrl + "/pay?view=notifications"));
        browserIntent.addCategory(Intent.CATEGORY_BROWSABLE);
        try {
            startActivity(browserIntent);
        } catch (ActivityNotFoundException error) {
            Toast.makeText(this, R.string.no_browser_message, Toast.LENGTH_LONG).show();
        }
    }

    private void openPaymentForm(String serverUrl, String target) {
        String handoffUrl = ServerUrl.paymentHandoff(serverUrl, target);
        if (handoffUrl == null) {
            showMessageScreen(
                    getString(R.string.invalid_link_title),
                    getString(R.string.invalid_link_message));
            return;
        }

        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(handoffUrl));
        browserIntent.addCategory(Intent.CATEGORY_BROWSABLE);
        try {
            startActivity(browserIntent);
            finish();
        } catch (ActivityNotFoundException error) {
            showMessageScreen(
                    getString(R.string.no_browser_title),
                    getString(R.string.no_browser_message));
        }
    }

    private TextView text(String value, int sizeSp, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sizeSp);
        view.setTextColor(color);
        return view;
    }

    private ImageView logo() {
        ImageView image = new ImageView(this);
        image.setImageResource(R.drawable.bolt12_pay_logo);
        image.setContentDescription(getString(R.string.app_name));
        image.setScaleType(ImageView.ScaleType.FIT_CENTER);
        return image;
    }

    private LinearLayout.LayoutParams centered(int width, int height, int top, int bottom) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(width, height);
        params.gravity = Gravity.CENTER_HORIZONTAL;
        params.topMargin = top;
        params.bottomMargin = bottom;
        return params;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
