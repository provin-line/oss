package keybinding

// IssueBody issues b with edit applied to the body before it is signed, to
// build the shapes Issue never emits.
var IssueBody = issueBody

// IssueStatusListEncoded issues a status list with encodedList as given.
var IssueStatusListEncoded = issueStatusListEncoded

// IssueStatusListBody issues a status list with encodedList as given and edit
// applied to the body before it is signed.
var IssueStatusListBody = issueStatusListBody

// StatusListHash is l's content hash, the one VerifyStatusList compares.
func StatusListHash(l *StatusList) string { return l.hash }
