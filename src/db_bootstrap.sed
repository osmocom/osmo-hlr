# Input to this is sql/hlr.sql.
#
# We want each SQL statement line wrapped in "...\n", and each end (";") to
# become a comma:
#
#   SOME SQL COMMAND (
#     that may span )
#   MULTIPLE LINES;
#   MORE;
#
# -->
#
#   "SOME SQL COMMAND (\n"
#   "  that may span )\n"
#   "MULTIPLE LINES\n",   <--note the comma here
#   "MORE\n",
#
# just replacing ';' with '\n,' won't work, since sed is bad in printing
# multiple lines. Also, how to input newlines to sed is not portable across
# platforms.

# Match excluding a trailing ';' as \1, keep any trailing ';' in \2
s/^\(.*[^;]\)\(;\|\)$/"\1\\n"\2/
# Replace trailing ';' as ','
s/;$/,/
