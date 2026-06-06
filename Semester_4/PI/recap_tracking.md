# Recap Tracking

## Part 1: Mechanisms for Collecting Personal Data (Recap from slide 39)

**1. Cookies: what was their need and what are their disadvantages today?**

Cookies were invented for five main purposes: authentication (remembering login state), personalization (storing user preferences like language), shopping carts (persisting items across sessions), analytics (tracking how users interact with a site), and ad targeting (tracking browsing history for relevant ads). *(Slide 5)*

Their disadvantages today include privacy concerns — cookies enable advertising networks to build detailed profiles of user interests and behavior across multiple websites. They also pose security risks, since cookies can store sensitive information like login credentials that could be accessed if a device is compromised. Additionally, malicious cookies can potentially deliver malware. *(Slide 6)*

**2. Explain web-tracking with 3rd party cookies.**

When a user visits a webpage, the browser downloads content from third parties (e.g., ad networks) embedded in the page. These third parties set their own cookies. If the user later visits a different, unrelated website that also embeds content from the same third party, the cookie is sent back, allowing the third party to track the user across both sites. The third party learns about the first-party page URL through the HTTP referrer header, and if a script tag is embedded, it can also access the page title. Users can restrict this by refusing to send cookies to third-party requests or refusing to process Set-Cookie headers in third-party responses. *(Slides 4, 10–11)*

**3. Describe other tracking methods which make use of the storage of the user (browser, etc).**

Beyond standard HTTP cookies, storage-based tracking methods include: CSS history sniffing (exploiting the CSS `:visited` property and `getComputedStyle()` to determine which links a user has previously visited), ETags (HTTP cache headers normally used for cache control but repurposed to assign unique persistent identifiers to users — the ID persists across sessions, browser restarts, and even computer reboots without using cookies), and Evercookies (a JavaScript API that stores cookie data in multiple browser storage mechanisms simultaneously, making it extremely difficult to delete). *(Slides 7, 12–13, 16–18)*

**4. Why does cookie-less tracking become relevant?**

Three main reasons: First, GDPR regulation treats cookies as personal data, requiring user consent. Second, browser restrictions — most browsers have stopped supporting third-party cookies, with Google Chrome completing this change in 2024. Third, the increasing use of ad blockers, which block ads and the data sent to analytics services like Google Analytics. *(Slide 19)*

**5. Which mechanisms use cookie-less tracking?**

Cookieless tracking works through several mechanisms: event tracking (server-side tracking of page views, clicks, and form submissions), server log analysis (analyzing request logs containing IP addresses, user agents, and other data), and API tracking (tracking user behavior on third-party platforms like social media or mobile apps via server-side code). A clientID is created either via a first-party cookie with a persistent ID (if consent is given) or by hashing the user's IP address, user agent, and website URL on the server side. *(Slides 19–20)*

**6. How is browser fingerprinting used for tracking user behaviour and what can be done to avoid it?**

Browser fingerprinting works independently of cookies by collecting data the browser sends — user agent string, HTTP accept headers, screen resolution, timezone, installed plugins, system fonts, and more — to create a unique identifier for a device. About 83% of browsers have a unique fingerprint. Combined with an IP address, a fingerprint can act as a cookie regenerator (supercookie) and serve as a global identifier. *(Slides 21–22)*

Defenses include using Tor Browser or NoScript for Firefox, which reduce fingerprinting ability. Brave browser adds subtle noise to APIs commonly used for fingerprinting, making you look different to fingerprinting scripts without breaking websites. There is a paradox, however: enhancing privacy settings can actually make fingerprinting easier, since unusual configurations stand out more than default ones. The EFF's "Cover Your Tracks" tool helps users assess their browser's fingerprint uniqueness. *(Slides 23, 26–27)*

**7. What is pixel-tracking and how does it work?**

A tracking pixel is a tiny (1×1 pixel) graphical element, usually transparent or hidden, embedded in the HTML code of websites or emails. When the user loads the page or opens the email, the pixel image is fetched from an external server (e.g., Facebook), which logs the page view along with the user's IP address and other data. It doesn't require scripts and works in the background without the user's awareness or consent. This raises privacy issues because a specific (non-anonymized) user is tracked, it can monitor email opens (e.g., newsletters), and data can be transferred to international companies. *(Slides 24–25)*

**8. How do search engines threaten our privacy?**

Search engines threaten privacy in three ways: search terms reveal your thoughts, work, problems, and even intelligence level; search dates disclose work/leisure patterns and the frequency of recurring topics; and IP addresses disclose your location and link all your searches together. Search engines typically collect and retain all of this personally identifiable information — Google and Microsoft keep IP addresses for 6 months. The 2006 AOL database disclosure demonstrated the risk: AOL published three months of search records for 658,000 users, and even though the data was "anonymized" with numeric IDs, users could be re-identified from their search patterns. *(Slides 30–31, 36)*

**9. How does "Startpage" search engine enhance search privacy?**

Startpage delivers actual Google search results while protecting user privacy. It is GDPR-compliant and based in the Netherlands, US, and India. Key features include: IP address protection (replacing your IP with 0.0.0.0), an "Anonymous View" feature that uses a proxy server when opening search results so users can browse result pages privately, no personalized ranking (all users get the same results), and submission to third-party audits. Its code is proprietary but externally audited. *(Slide 37)*

---

## Part 2: Tracking by Processing Personal Data (Recap from slide 32)

**1. Predictive analytics**

Predictive analytics uses data mining to extract rules, information, and behavioral patterns from raw data. It employs statistical methods (cluster analysis, classification, association analysis, regression analysis) and machine learning. A key example is the US supermarket Target, which analyzed buying behavior to identify pregnant customers based on purchasing frequency of 25 specific products (lotions, soaps, cotton, supplements), then targeted them with relevant advertising. The big data approach emphasizes correlations over causality and accepts some uncertainty in exchange for working with much larger datasets. *(Slides 3–4 of Part 2)*

**2. How were personality traits predicted from smartphone data?**

The study by Chittaranjan et al. (2011, with Nokia Research in Switzerland) collected smartphone usage data aggregated monthly, including: application usage (office, internet, video/music, maps, mail, YouTube, calendar, camera, chat, SMS, games), call patterns (incoming/outgoing counts, durations, unique contacts, missed calls), Bluetooth data (unique device IDs seen, frequency of sightings), and SMS details (word lengths, message counts). These features were correlated with the Big Five personality traits (Extraversion, Agreeableness, Conscientiousness, Neuroticism/Emotional Stability, Openness to Experience). For example, extraversion correlated negatively with internet use (-0.26) and positively with incoming call duration (0.20). Classification accuracy ranged from 69.3% (Openness) to 75.9% (Extraversion), significantly above chance baselines of 52–62%. *(Slides 7–10 of Part 2)*

**3. What can be done against tracking apps?**

Apple's App Tracking Transparency (ATT), introduced in iOS 15 (2021), requires all apps to ask user permission before forwarding data to third parties. If the user allows tracking, apps receive an advertising identifier (IDFA) instead of directly identifying information. If the user selects "do-not-track," no IDFA is provided and the app must still function. This significantly reduced uncontrolled user tracking by apps, though it was criticized by Meta and Google. More broadly, apps are described as more dangerous than browser tracking because they are "black boxes" — users often don't know what data they disclose, and privacy tools like Tor or Brave don't help with app-level tracking. *(Slides 15–16 of Part 2)*

**4. How can tracking data be used in predicting personal health and fitness status?**

Insurance company Aviva developed a model to replace routine health checks with predictions derived from marketing data about consumption habits, lifestyle, and income, aiming to identify risks for diabetes, high blood pressure, and depression — with results nearly as accurate as blood tests. Fitness trackers like Fitbit record steps, paths, walking time, calories, sleep hours, and allow manual entry of meals, blood pressure, sugar levels, and heart rate. The business model involves selling devices to employers and insurance companies, promising fewer sick days and better productivity. In the US, where 62% of health insurance is employer-paid, companies using Fitbit data can negotiate lower insurance premiums. *(Slides 20–21 of Part 2)*

**5. Describe the car insurance use case that uses a tracking box.**

Insurance telematics (usage-based insurance) uses a vehicle tracking box containing a GPS system, motion sensor/accelerometer, SIM card, and software. The box records when and where you drive, road types, speed on different roads, sharp braking or acceleration, breaks taken on long journeys, motorway miles, total mileage, and total number of journeys. This data is used to assess car insurance risk based on actual driving behavior, calculate renewal premiums, reward safe drivers with bonus miles, assist after accidents, track stolen vehicles, and manage claims. The company states it won't share driving data unless required by law or in cases of suspected fraud. *(Slides 22–24 of Part 2)*

**6. Social Bots: how do they work, what are their impacts on users, and other targets?**

A social bot is a fake user account operated by code with a task list. In non-malicious form, bots collect user preferences and automate marketing. In malicious form, they collect information from users, generate fake engagement (likes), and manipulate users into accepting false narratives. Bots can be purchased cheaply (around 50 cents each) from bot farms in countries like China, Russia, Qatar, and Iran. More sophisticated bots have realistic profiles with names, photos, biographies, and can engage in conversations — costing hundreds to thousands of dollars each. *(Slides 26–28 of Part 2)*

Their impacts include: spying on users by classifying them based on reactions and response times into categories stored in databases; manipulating elections (bot networks amplified conspiracy theories in the 2020 US election, generated over 3 billion views before the Brexit vote, and spread fake videos in Germany's 2025 election); creating deception where voters can't distinguish real from artificial engagement; reinforcing echo chambers and polarization; and enabling foreign interference in democratic processes. Simple bots can be detected through pattern analysis (cartoon profile pictures, reposting rates, temporal anomalies, engagement rate analysis), but sophisticated bots are increasingly difficult to identify. *(Slides 29–31 of Part 2)*
