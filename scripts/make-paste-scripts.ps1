<#
.SYNOPSIS
    Writes paste-ready copies of the Windows Server scripts, for servers that refuse unsigned
    script files.

.DESCRIPTION
    A Group Policy that requires signed scripts (AllSigned) overrides the -ExecutionPolicy Bypass
    of install-windows.cmd and upgrade-windows.cmd, and Unblock-File does not help against it.
    The policy covers script files, not commands typed or pasted, so each script is also shipped
    as one block to paste into PowerShell opened as Administrator. Found on a real server in
    November 2026.

    Made from the scripts by PowerShell's own parser, never by hand, so they cannot drift apart:
      - the param block becomes settings at the top of the block, with the same defaults;
      - common.ps1 is put in, instead of being dot-sourced;
      - $PSScriptRoot points at the bundle's windows folder, from a $BundleFolder setting;
      - exit, which would close the window, becomes return (exit 0) or throw (any other code).

    Called by build-offline-bundle.ps1. Run by hand to check: it fails if a script uses exit
    where it cannot be converted safely.

.EXAMPLE
    .\scripts\make-paste-scripts.ps1 -WindowsDir deploy\windows -OutDir var\paste -Version 0.5.2
#>
param(
    [Parameter(Mandatory)][string]$WindowsDir,
    [Parameter(Mandatory)][string]$OutDir,
    [Parameter(Mandatory)][string]$Version
)
$ErrorActionPreference = "Stop"
$Lang = [Management.Automation.Language.Parser]

function Read-Ast([string]$Path) {
    $tokens = $null; $errors = $null
    $ast = $Lang::ParseFile((Resolve-Path $Path).Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw "$Path does not parse: $($errors[0].Message) (line $($errors[0].Extent.StartLineNumber))" }
    return $ast
}

# Inside a function or a script block, `return` would leave only that, so exit must become throw.
function Test-Nested($node) {
    for ($p = $node.Parent; $p; $p = $p.Parent) {
        if ($p -is [Management.Automation.Language.FunctionDefinitionAst]) { return $true }
        if ($p -is [Management.Automation.Language.ScriptBlockExpressionAst]) { return $true }
    }
    return $false
}

# The script's text after its param block, with exit, $PSScriptRoot and the dot-sourcing of
# common.ps1 replaced.
function Convert-Body($ast, [string]$Name) {
    $text = $ast.Extent.Text
    $cut = if ($ast.ParamBlock) { $ast.ParamBlock.Extent.EndOffset } else { 0 }
    $edits = New-Object System.Collections.ArrayList

    $dots = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.InvocationOperator -eq "Dot" }, $true))
    foreach ($d in $dots) {
        if ($d.Extent.Text -notmatch 'common\.ps1') { throw "$Name dot-sources something other than common.ps1: $($d.Extent.Text)" }
        [void]$edits.Add(@($d.Extent.StartOffset, $d.Extent.EndOffset, "# (common.ps1 is pasted above)"))
    }
    $inDot = { param($n) @($dots | Where-Object { $n.Extent.StartOffset -ge $_.Extent.StartOffset -and $n.Extent.EndOffset -le $_.Extent.EndOffset }).Count -gt 0 }

    foreach ($v in $ast.FindAll({ param($n) $n -is [Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -eq "PSScriptRoot" }, $true)) {
        if (-not (& $inDot $v)) { [void]$edits.Add(@($v.Extent.StartOffset, $v.Extent.EndOffset, '$WindowsFolder')) }
    }
    foreach ($x in $ast.FindAll({ param($n) $n -is [Management.Automation.Language.ExitStatementAst] }, $true)) {
        $code = if ($x.Pipeline) { $x.Pipeline.Extent.Text.Trim() } else { "0" }
        $nested = Test-Nested $x
        if ($code -eq "0" -and $nested) { throw "$Name has 'exit 0' inside a function or script block (line $($x.Extent.StartLineNumber)); it cannot be pasted safely." }
        $new = if ($code -eq "0") { "return" } else { 'throw "Stopped: see the messages above. (exit ' + $code + ')"' }
        [void]$edits.Add(@($x.Extent.StartOffset, $x.Extent.EndOffset, $new))
    }
    foreach ($e in $edits) { if ($e[0] -lt $cut) { throw "$Name has something to convert inside its param block." } }
    foreach ($e in @($edits | Sort-Object { $_[0] } -Descending)) {
        $text = $text.Substring(0, $e[0]) + $e[2] + $text.Substring($e[1])
    }
    return $text.Substring($cut).Trim("`r", "`n")
}

# The param block as settings: "$Port = 8080".
function Convert-Params($ast) {
    if (-not $ast.ParamBlock) { return @() }
    foreach ($p in $ast.ParamBlock.Parameters) {
        $name = $p.Name.VariablePath.UserPath
        $value = if ($p.StaticType -eq [switch]) { '$false' }
            elseif ($p.DefaultValue) { $p.DefaultValue.Extent.Text }
            elseif ($p.StaticType -eq [string]) { '""' }
            else { '$null' }
        "{0,-17} = {1}" -f "`$$name", $value
    }
}

$common = Read-Ast (Join-Path $WindowsDir "common.ps1")
$commonBody = Convert-Body $common "common.ps1"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

foreach ($name in @("install-windows", "upgrade-windows", "uninstall-windows")) {
    $ast = Read-Ast (Join-Path $WindowsDir "$name.ps1")
    $settings = @(Convert-Params $ast) -join "`n"
    $body = Convert-Body $ast "$name.ps1"
    $text = @"
& {
# ===================== SBOM Platform $Version - $name, to paste =====================
# For a server whose policy refuses unsigned script files ("is not digitally signed", even from
# $name.cmd): paste this whole block into PowerShell opened as Administrator. It is
# windows\$name.ps1 with common.ps1 put in; nothing else differs. Made by
# scripts/make-paste-scripts.ps1 - do not edit.

# ---- Settings: the options of $name.cmd (README.md, "Windows Server") -------------
`$BundleFolder    = "C:\sbom-platform-offline-$Version"   # where this bundle was unzipped
$settings
# -------------------------------------------------------------------------------------------

if (`$ExecutionContext.SessionState.LanguageMode -ne "FullLanguage") {
    throw "PowerShell runs in `$(`$ExecutionContext.SessionState.LanguageMode) mode here (application control). The scripts cannot run, pasted or not: ask IT to sign them or allow them."
}
`$WindowsFolder = Join-Path `$BundleFolder "windows"
if (-not (Test-Path (Join-Path `$WindowsFolder "common.ps1"))) {
    throw "`$BundleFolder is not the unzipped bundle: set `$BundleFolder at the top of the block."
}

# ---- common.ps1 ---------------------------------------------------------------------------
$commonBody

# ---- $name.ps1 ----------------------------------------------------------------------------
$body
}
"@
    $text = $text.Replace("`r`n", "`n")
    $bad = [regex]::Matches($text, '[^\x09\x0A\x20-\x7E]')
    if ($bad.Count -gt 0) { throw "$name has non-ASCII characters; Windows PowerShell 5.1 would misread them." }

    # The result must parse, and hold no exit and no $PSScriptRoot.
    $tokens = $null; $errors = $null
    $check = $Lang::ParseInput($text, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw "The paste version of $name does not parse: $($errors[0].Message) (line $($errors[0].Extent.StartLineNumber))" }
    if ($check.FindAll({ param($n) $n -is [Management.Automation.Language.ExitStatementAst] }, $true).Count -gt 0) { throw "The paste version of $name still has exit." }
    if ($text -match '\$PSScriptRoot') { throw "The paste version of $name still uses `$PSScriptRoot." }

    $out = Join-Path $OutDir "$name-paste.txt"
    [IO.File]::WriteAllText($out, $text.Replace("`n", "`r`n"), (New-Object Text.ASCIIEncoding))
    Write-Host ("    windows/{0}-paste.txt ({1} lines)" -f $name, ($text -split "`n").Count)
}
