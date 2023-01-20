package data.installer

import Errors
import com.github.ajalt.clikt.core.CliktError
import com.github.ajalt.mordant.rendering.TextColors
import com.github.ajalt.mordant.rendering.TextColors.brightGreen
import com.github.ajalt.mordant.rendering.TextColors.brightYellow
import com.github.ajalt.mordant.terminal.ConversionResult
import com.github.ajalt.mordant.terminal.Terminal
import data.InstallerManifestData
import data.PreviousManifestData
import input.InstallerSwitch
import input.Prompts
import org.koin.core.component.KoinComponent
import org.koin.core.component.get
import org.koin.core.component.inject
import schemas.SchemasImpl
import schemas.data.InstallerSchema
import schemas.manifest.InstallerManifest

object InstallerSwitch : KoinComponent {
    private val installerManifestData: InstallerManifestData by inject()
    private val previousManifestData: PreviousManifestData by inject()

    fun Terminal.installerSwitchPrompt(installerSwitch: InstallerSwitch) {
        if (
            installerManifestData.installerType == InstallerManifest.Installer.InstallerType.EXE
            || installerSwitch == InstallerSwitch.Custom
        ) {
            val isRequired = installerManifestData.installerType == InstallerManifest.Installer.InstallerType.EXE &&
                    installerSwitch != InstallerSwitch.Custom
            switchInfo(installerManifestData.installerType, installerSwitch).also { (info, infoColor) ->
                println(infoColor(info))
            }
            info(switchExample(installerSwitch))
            installerManifestData.installerSwitches[installerSwitch] = prompt(
                prompt = colors.brightWhite(installerSwitch.toString()),
                default = getPreviousValue(installerSwitch)?.also { muted("Previous $installerSwitch: $it") },
                convert = {
                    val error = isInstallerSwitchValid(
                        switch = it,
                        installerSwitch = installerSwitch,
                        canBeBlank = !isRequired
                    )
                    if (error != null) {
                        ConversionResult.Invalid(error.message!!)
                    } else {
                        ConversionResult.Valid(it)
                    }
                }
            )?.takeIf { it.isNotBlank() }?.trim()
            println()
        }
    }

    private fun isInstallerSwitchValid(
        switch: String,
        installerSwitch: InstallerSwitch,
        canBeBlank: Boolean = false,
        installerSchema: InstallerSchema = get<SchemasImpl>().installerSchema
    ): CliktError? {
        val (minBoundary, maxBoundary) = installerSwitch.getLengthBoundary(installerSchema)
        return when {
            switch.isBlank() && !canBeBlank -> CliktError(Errors.blankInput(installerSwitch.toPromptType()))
            switch.length > maxBoundary -> CliktError(Errors.invalidLength(min = minBoundary, max = maxBoundary))
            else -> null
        }
    }

    private fun getPreviousValue(installerSwitch: InstallerSwitch): String? {
        return previousManifestData.remoteInstallerData?.let {
            when (installerSwitch) {
                InstallerSwitch.Silent -> {
                    it.installerSwitches?.silent ?: it.installers[installerManifestData.installers.size]
                        .installerSwitches?.silent
                }
                InstallerSwitch.SilentWithProgress -> {
                    it.installerSwitches?.silentWithProgress ?: it.installers[installerManifestData.installers.size]
                        .installerSwitches?.silentWithProgress
                }
                InstallerSwitch.Custom -> {
                    it.installerSwitches?.custom ?: it.installers[installerManifestData.installers.size]
                        .installerSwitches?.custom
                }
            }
        }
    }

    private fun switchInfo(
        installerType: InstallerManifest.Installer.InstallerType?,
        installerSwitch: InstallerSwitch
    ): Pair<String, TextColors> {
        val isRequired = installerManifestData.installerType == InstallerManifest.Installer.InstallerType.EXE &&
            installerSwitch != InstallerSwitch.Custom
        return buildString {
            append(
                when {
                    installerType == InstallerManifest.Installer.InstallerType.EXE &&
                        installerSwitch != InstallerSwitch.Custom -> Prompts.required
                    else -> Prompts.optional
                }
            )
            append(" Enter the ${installerSwitch.toString().lowercase()} install switch")
        } to if (getPreviousValue(installerSwitch).isNullOrBlank() && isRequired) brightGreen else brightYellow
    }

    private fun switchExample(installerSwitch: InstallerSwitch): String {
        return buildString {
            append("Example: ")
            append(
                when (installerSwitch) {
                    InstallerSwitch.Silent -> "/S, -verysilent, /qn, --silent, /exenoui."
                    InstallerSwitch.SilentWithProgress -> "/S, -silent, /qb, /exebasicui."
                    InstallerSwitch.Custom -> "/norestart, -norestart"
                }
            )
        }
    }
}
