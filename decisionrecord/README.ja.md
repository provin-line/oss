# decisionrecord — 判定ごとの記録
> 日本語版 — English: [README.md](README.md)

判定する部品（関門、境界の段、配送の判定）は、判定ごとに `Record` を 1 つ出す。中身は、判定の ID、判定した部品、時刻、結果、拒否か保留した検査と理由、判定が帰属する主体、判定の対象の content address、部品ごとの欄である。中身の値（payload）は持たない。

`Filter` は、明示して選んだ水準で、記録を `Sink` に書く。

| 水準 | 書くもの | 記録が書けないとき |
| --- | --- | --- |
| `all` | すべての記録 | error を返す。判定する部品は判定を拒否に倒す |
| `refusals` | 受け入れ以外の判定だけ（拒否、held、unenforced） | 警告。判定は変えない |
| `summary` | `Flush` ごとに、部品ごとの `Summary`（結果と検査ごとの数） | 警告 |
| `none` | 何も書かない | — |

ゼロ値の水準は断るので、水準は選んだときだけ効く。判定する部品の決まりは 1 つだけ:「`Filter.Record` が error を返したら拒否する」。`all` より下の水準では、記録が書けなくても判定は変わらないので、unenforced の判定は記録なしで先へ進むことがある。unenforced の判定を記録なしで通してはならない部品は `all` を選ぶ。形の誤った記録（`Record.Validate`）は、`none` を含むどの水準でも error になる。書き出し先の誤りではなく、書いた側の誤りだからである。ここの書き出し先は、書き出し先に直に書く呼び手のために、記録と要約（`Summary.Validate`）も確かめる。

結果は 4 つある（`held` は形の版 2 だけ）。`accepted`（どの検査も拒否も保留もせず、判定する部品は判定の対象を受け入れると決めた。後で拒否したら、それも記録する）、`refused`（止める検査が拒否し、部品は対象を止めた。対象は先へ進まなかった）、`unenforced`（拒否したのが、止めずに記録だけする検査だけだったので、部品は対象を止めなかった。対象は先へ進んだかもしれない）、`held`（止める検査が判定を後に回した。対象は先へ進んでおらず、後で別の `DecisionID` で判定し直されることがある）。記録は、判定する部品が判定した時、対象を実際に進める前に書く（進めるのは部品自身か、部品が答える相手）。拒否と held の判定は先へ進まなかった。受け入れと unenforced の判定については、対象が先へ進んだかどうかは記録からは分からず、読む側は、先へ進んだかもしれないものとして読む。

受け入れとして記録した後に拒否した判定は、同じ `DecisionID` でもう一度記録する。判定の結果は、読む順によらず、その ID の記録のうち一番強いものとする。記録の**どれか**が拒否なら拒否、そうでなく unenforced があれば unenforced、そうでなく held があれば held、どれも無ければ受け入れ。書く側は、1 つの判定を受け入れとして何回でも記録し、その後に unenforced か拒否のどちらかを高々 1 回だけ記録し、その後は何も記録しない（書く側は、書くときに結果を知っている）。held の判定は記録を held の 1 つだけ持つ。後に回したものを判定し直すときは、別の `DecisionID` の別の判定にする。1 つの判定の記録は前の記録が受け取られてから書く。そうすれば要約の水準は判定を 1 回ずつ数える。要約の水準が覚える ID は受け入れた判定の分だけなので、memory は判定する部品が認めた分で抑えられ、誰でも起こせる拒否、held、unenforced では増えない。ほかの拒否、held、unenforced は来たときに数える。この決まりを破ると、要約が判定を 2 回以上数えるか、その結果の最初の記録の検査で数えるだけで、記録のうち一番強い結果より弱い結果では数えない。ほかは何も変わらない。数は結果と検査ごとに持ち、検査は判定する部品が決めた固定の名前である。受け入れ以外には拒否か保留した検査を書き、受け入れには書かない。`Evidence` は役割と content address（`contentaddress.Address`）の順序つきの列で、値は入れない。主体は、ID、判定した部品と同じく、空でない正しい UTF-8 でなければならない（読む側が key にするため）。時刻は 0000〜9999 年。人が読む文字列（理由、属性の値）は、正しくない UTF-8 を置き換えて書くので、記録が自分の bytes で失われない。要約の数は 0 から 2^53−1（`int64`）で、JSON の数で書き、結果、検査の順に、どちらも文字列として比べて並べ（結果は `accepted`、`held`、`refused`、`unenforced` の順）、重ねない。

書き出し先は並行に使えなければならず、`all` の水準では、記録が残ってから nil を返す（buffer しない writer か、sync した writer）。

- `NewJSONLines`: 1 行に RFC 8785 の JSON を 1 つ。`"v"`（形の版）と `"kind"` を持つ。時刻は UTC で小数 9 桁なので、文字列のまま並べられる。行は `"\n"` だけで分ける（U+2028 と U+2029 はそのまま書く）。writer には `Write` を 1 つずつ渡す。`Write` が終わる前に呼び出しが返っても同じである。書けなかった後の行は、新しい行から始める。
- `NewLog`: 記録か要約ごとに構造化ログを 1 件。handler を通すので、info を取らない logger や、失敗した handler は error になる。残さずに nil を返す handler は見分けられないので、`all` では nil が「残した」を意味する handler を使う。ログの 1 件は、JSON の 1 行の member を、`"v"` も含めて属性として持つ。

これらの書き出し先は、呼び出しの context が終わったら、書き込みの終わりを待たずにすぐ返す。error は `ctx.Err()` を包み（`errors.Is` で `context.DeadlineExceeded` か `context.Canceled` に当たる）、どの書き出し先かと、書き込みを始めなかったか、始めたかもしれないかを言う。書き込みを始める前に context が終わった記録は、そのときも後でも書かない。始めた書き込みは止められず、呼び出しが返った後に書き終わり、残ることがある。終わらない書き込みは、終わるまで、その書き出し先のほかの書き込みを待たせることがある。そのときも、それぞれの呼び出しは自分の context の終わりで返る。永久に終わらない書き込み（ずっと詰まった writer や handler）は取り戻せず、書き出し先ごとに 1 つまで残る。終わりえない context（`context.Background()` や `context.WithoutCancel` で作ったもの）では、0.4.0 と同じく、終わらない書き込みの後ろでも書き込みを待つ。nil の context は `context.Background()` として扱う。writer や handler の panic は呼び手に届く。終わりえない context では、書き込みは呼び手の goroutine で走り、panic はそのまま届く。終わりうる context では、書き込みは自分の goroutine で走り、panic は値と書き手の stack を持つ `*decisionrecord.WritePanic` として届く（その文は両方を書き、値が error なら `Unwrap` がそれを返す）。ただし、書き出し先が panic を渡す前に呼び出しが context の終わりで返っていたら、panic は捨て、その書き込みは失敗したものとする。writer や handler が書き出し先自身の goroutine の中で `runtime.Goexit` を呼ぶと、その書き込みは失敗する。呼び手の goroutine の中で呼ぶと、ほかの場所と同じくその goroutine が終わり、呼び出しは返らない。どちらでも、書き出し先はその後も書く。

`all` の水準では、`Filter.Record` が error を返した記録も残ることがある。始めた書き込みは呼び出しが返った後に書き終わることがあり、writer や handler が記録を残したうえで error を返すこともある。そこで判定を拒否に倒し、読み手に拒否を見せたい部品は、同じ `DecisionID` で拒否の記録を、同じ `Filter` を通してもう一度書く。判定の結果は記録のうち一番強いものになる。1 つの判定の記録の決まりは、error を返したその `Filter` を通すこの拒否を許す。

`all` より下の水準で、`Filter` が書き出し先の失敗を知らせる警告も、context の終わりを過ぎて待たない。ほかの警告を書いていなければ、context が終わっていても遅れて書く。ほかの警告を書いている間に context が終わったら、書かない。警告の handler も上の handler と同じ扱いになる。その panic は `Filter.Record` や `Filter.Flush` の呼び手に同じように届く。handler が警告自身の goroutine の中で `runtime.Goexit` を呼ぶと、その警告は失われる。呼び手の goroutine の中で呼ぶと、その goroutine が終わる。どちらでも、`Filter` はその後も警告を書く。`Filter.Flush` は、呼んだ時に context がもう終わっていたら、その error を返し、窓を数ごと次の `Flush` に持ち越す。`Flush` の途中で context が終わったら、窓は持ち越さない。そのときまでに書き込みを始めていない要約は、書き出し先が書けなかった要約と同じく失われ、要約ごとに、残るのは多くて警告 1 つである。書き込みを始めていた要約は残ることがある。最後の窓の要約を終了の合図で失わないために、終了時の最後の `Flush` には、終了の合図では終わらず、自分の期限を持つ context を渡す（例: `context.WithTimeout(context.WithoutCancel(ctx), d)`）。期限が無いと、終わらない書き込みの後ろで永久に待ちうる。先に期限を過ぎれば、それまでに書いていない分の数は、上と同じく失われる。書けなかった要約はやはり失われる。`Flush` がある point の要約を書く間に起きた panic（書き出し先の中でも、要約を書けなかった警告の handler の中でも）は、`Flush` がその後のすべての point の要約を書いてから、起きたままの形で、自分の stack と共に呼び手に届く。呼び手の goroutine の中の `runtime.Goexit` も同じ。`Flush` は panic した書き出し先を続けて呼ぶので、ここで作ったものでない書き出し先は、panic の後も呼べるようにしておく。panic が呼び手に届くのは、それらの書き込みが返った後になる。それらの書き込みの中の panic は、その point の要約を書けなかった警告になり、panic の値を持つ。その警告の handler の panic は捨てる。それらの書き込みやその警告の中の panic や `runtime.Goexit` も、残りの書き込みを止めない。それらの書き込みやその警告の中で、呼び手の goroutine の `runtime.Goexit` が起きると、残りを書いた後にその goroutine は終わり、それより前の panic は（`runtime.Goexit` が途中で止めるので）呼び手に届かない。

## 形の版

書き出し先は 1 つの形の版で書き、それが各行・各件の `"v"` になる。`NewJSONLines` と `NewLog` は、0.4.0 と同じく版 1 で書く。`NewJSONLinesFormat` と `NewLogFormat` は渡された版（`FormatV1` か `FormatV2`）で書き、それ以外の版は断る。

| 版 | 足すもの |
| --- | --- |
| 1 | 上の member。結果は `accepted`、`refused`、`unenforced` |
| 2 | 結果 `held`。記録の `"refusedAt"` と `"verifiedHops"` |

版 2 の記録は、次を持てる。

- `"refusedAt"`: 拒否か unenforced の判定だけが持つ、その拒否を診断した位置。判定の対象が通ってきた 1 歩（hop）を、判定する部品の語で書く（主体と同じ扱い）。held の判定は拒否されていないので持たない。`{"hop": "…", "confidence": "…"}` で、confidence は `claimed`（hop を、署名を確かめる前に、判定の対象が名乗ったとおりに書いた）、`verified`（署名を確かめた後に書いた）、`unknown`（検査は hop に関わるが、部品がそれを名指せない。このとき `"hop"` は書かない）のどれか。
- `"verifiedHops"`: 部品が署名を確かめた hop を、順に並べたもの。結果を問わず持てる。無いときは member を書かない。

confidence は位置だけを格付けする（hop の名がどこまで確かめられたか）。検証の判定（`vc` の `ConfidenceState` の failed・indeterminate・verified）とは別の尺度で、`verified` は、判定の対象やその検証が verified だとは言わない。`"refusedAt"` と `"verifiedHops"` は互いに独立で、confidence が `verified` の `"refusedAt"` の hop が `"verifiedHops"` に入っているとは限らない。

版 1 の書き出し先は、版 1 で表せないもの（`held` の結果、`RefusedAt`、確かめた hop、`held` の判定の数）を渡されると、`ErrNotInFormat` に当たる error を返し、何も書かない。`all` の水準では、判定する部品は判定を拒否に倒す。`summary` の水準では、`Filter` は書き出し先の版を知らないので、窓の中に `held` の判定が 1 つあると、版 1 の書き出し先はその部品のその窓の要約を、数を全部含めて断り、`Filter` が警告する。判定を保留する部品は版 2 で書く。`Record.Validate` は、版によらず版 2 の member も確かめる。

次のどれかが変わるときは、必ず版を上げる: member、member の値の形か意味、`"kind"`・`"outcome"`・`"confidence"` の値の集まり、ログの書き出し先では 1 件の message か level。同じ版の中では、どれも変えない。知らない member を断る読み手も、知っている版の行はすべて読める。`"check"` の値と `"attributes"` の名前は判定する部品の語なので、版によらず増えうる。

`NewFilter` で作っていない `Filter` は、すべての呼び出しを断る。この package は、関門が送り直しを断るために持つ使い済みの nonce の記録ではない。
