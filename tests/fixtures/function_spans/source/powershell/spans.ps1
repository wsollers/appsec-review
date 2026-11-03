$limit = 4 # ANCHOR:none

function Get-Items { # BEGIN:Get-Items
    param([string[]]$Names)
    <# a block comment with a brace {
    #>
    $Names | ForEach-Object {
        Write-Output "item: $_ }" # ANCHOR:Get-Items
    }
    return $Names.Count # ANCHOR:Get-Items
} # END:Get-Items

class Spans {
    [int] Count([string[]]$items) { # BEGIN:Count
        return $items.Length # ANCHOR:Count
    } # END:Count
}
