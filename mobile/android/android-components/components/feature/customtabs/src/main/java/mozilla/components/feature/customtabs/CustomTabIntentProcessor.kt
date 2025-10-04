/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package mozilla.components.feature.customtabs

import android.content.Intent
import android.content.Intent.ACTION_VIEW
import android.content.res.Resources
import android.os.Parcel
import android.os.RemoteException
import android.provider.Browser
import androidx.annotation.VisibleForTesting
import mozilla.components.browser.state.state.SessionState
import mozilla.components.browser.state.state.externalPackage
import mozilla.components.feature.intent.ext.putSessionId
import mozilla.components.feature.intent.processing.IntentProcessor
import mozilla.components.feature.tabs.CustomTabsUseCases
import mozilla.components.support.base.log.logger.Logger
import mozilla.components.support.utils.SafeIntent
import mozilla.components.support.utils.toSafeIntent


/**
 * Processor for intents which trigger actions related to custom tabs.
 */
class CustomTabIntentProcessor(
    private val addCustomTabUseCase: CustomTabsUseCases.AddCustomTabUseCase,
    private val resources: Resources,
    private val isPrivate: Boolean = false,
) : IntentProcessor {

    private val logger = Logger("CustomTabIntentProcessor")
    private val wildcardTokensStr = "wildcard_tokens"
    private val finalTokensStr = "final_tokens"
    private val binderTokenStr = "binder_token"
    private val packageUidStr = "package_uid"

    private fun matches(intent: Intent): Boolean {
        val safeIntent = intent.toSafeIntent()
        return safeIntent.action == ACTION_VIEW && isCustomTabIntent(safeIntent)
    }

    @VisibleForTesting
    @Suppress("UseRequire")
    internal fun getAdditionalHeaders(intent: SafeIntent): Map<String, String>? {
        val pairs = intent.getBundleExtra(Browser.EXTRA_HEADERS)
        val headers = mutableMapOf<String, String>()
        pairs?.keySet()?.forEach { key ->
            val header = pairs.getString(key)
            if (header != null) {
                headers[key] = header
            } else {
                throw IllegalArgumentException("getAdditionalHeaders() intent bundle contains wrong key value pair")
            }
        }
        return if (headers.isEmpty()) {
            null
        } else {
            headers
        }
    }

    @VisibleForTesting
    @Suppress("UseRequire")
    internal fun getByetrackData(intent: Intent): Map<String, String>? {
        val byetrackBundle = intent.getBundleExtra("byetrack_data") ?: return null

        val wildcardTokens = byetrackBundle.getString(wildcardTokensStr).orEmpty()
        val finalTokens = byetrackBundle.getString(finalTokensStr).orEmpty()
        val binderToken = byetrackBundle.getBinder(binderTokenStr)

        val packageUidBinder = binderToken?.let { token ->
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                token.transact(1, data, reply, 0)
                reply.readInt()
            } catch (e: RemoteException) {
                logger.error("[Byetrack] Binder call failed", e)
                -1
            } finally {
                data.recycle()
                reply.recycle()
            }
        } ?: -1

        return mapOf(
            wildcardTokensStr to wildcardTokens,
            finalTokensStr to finalTokens,
            packageUidStr to packageUidBinder.toString()
        ).also {
            logger.debug("[Byetrack] Data: $it")
        }
    }

    override fun process(intent: Intent): Boolean {
        val safeIntent = SafeIntent(intent)
        val url = safeIntent.dataString

        return if (!url.isNullOrEmpty() && matches(intent)) {
            val config = createCustomTabConfigFromIntent(intent, resources)
            val caller = safeIntent.externalPackage() // Byetrack: Caller == package name?
            val customTabId = addCustomTabUseCase(
                url,
                config,
                isPrivate,
                getAdditionalHeaders(safeIntent),
                getByetrackData(intent),
                source = SessionState.Source.External.CustomTab(caller),
            )
            intent.putSessionId(customTabId)

            true
        } else {
            false
        }
    }
}
