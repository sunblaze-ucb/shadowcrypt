// initialize keys for demo
chrome.storage.sync.get(function (o) {
	if (Object.keys(o).length === 0) {
		chrome.storage.sync.set(
{
  "origin-http://www.reddit.com": {
    "defaultFingerprint": "0d26c1facd505778843e88b034ae695fe16db92ce0f480eb013b54ca9b93acdc",
    "keys": {
      "0d26c1facd505778843e88b034ae695fe16db92ce0f480eb013b54ca9b93acdc": {
        "color": 6,
        "name": "ShadowCrypt Users",
        "note": "ShadowCrypt comes with this key. Anyone can get it.",
        "passphrase": "wide open",
        "secret": [
          592810485,
          1756613978,
          3386531780,
          3914334371
        ]
      }
    },
    "rules": [
      {
		urlPattern: '',
		selector: '.captcha',
		noShim: true
	  },
      {
		urlPattern: '',
		selector: '[name=user]',
		noShim: true
	  },
      {
		urlPattern: '',
		selector: '[name=q]',
		off: true
	  }
	]
  },
  "origin-https://app.asana.com": {
    "defaultFingerprint": "98acda177e3fdadccfafccde193a4fb485fe61e0da45e3812a069031d16ba915",
    "keys": {
      "98acda177e3fdadccfafccde193a4fb485fe61e0da45e3812a069031d16ba915": {
        "color": 6,
        "name": "ShadowCrypt Users",
        "note": "ShadowCrypt comes with this key. Anyone can get it.",
        "passphrase": "wide open",
        "secret": [
          1466772937,
          2591219597,
          1223770414,
          772868465
        ]
      }
    },
    "rules": [
        {
            urlPattern: '[^&?]lg*',
            selector: "#email_input",
            noShim: true, 
        },

        {
            urlPattern: '[^&?]lg*',
            selector: "#password_input",
            noShim: true,
        },

        {
            urlPattern: '$',
            selector: "#nav_search_input",
            noShim: false,
            off: false,
            mode: "wordsQuery"
        },
    ]
  },
  "origin-https://mail.google.com": {
    "defaultFingerprint": "35edbab33e6939068818eab465968aa3eeee426bc37a571022f077da865a2c74",
    "keys": {
      "35edbab33e6939068818eab465968aa3eeee426bc37a571022f077da865a2c74": {
        "color": 6,
        "name": "ShadowCrypt Users",
        "note": "ShadowCrypt comes with this key. Anyone can get it.",
        "passphrase": "wide open",
        "secret": [
          1081330386,
          1897912442,
          1011823286,
          3617319768
        ]
      }
    },
    "rules": [
        {
            urlPattern: '/mail/',
            selector: "[name=q]",
            off: true,
            mode: "wordsQuery"
        },

        {
            urlPattern: "/mail/",
            selector: "[name=to],[name=cc],[name=bcc]",
            noShim: true
        },

        {
            urlPattern: "/mail$",
            selector: "[role=textbox]",
            mode: "words"
        }
    ]
  },
  "origin-https://twitter.com": {
    "defaultFingerprint": "4ff95cef5a76149b687f7b54908cd2fa168794e214cedf9ee1a5df1dfec13057",
    "keys": {
      "4ff95cef5a76149b687f7b54908cd2fa168794e214cedf9ee1a5df1dfec13057": {
        "color": 6,
        "name": "ShadowCrypt Users",
        "note": "ShadowCrypt comes with this key. Anyone can get it.",
        "passphrase": "wide open",
        "secret": [
          3974799740,
          158280801,
          3624313247,
          1839113757
        ]
      }
    },
    "rules": [
        {
            urlPattern: '$',
            selector: ".email-input",
            noShim: true, 
            off: true,
            mode: "none"
        },

        {
            urlPattern: 'login',
            selector: ".js-password-field",
            noShim: true,
            off: true,
            mode: "none"
        },

        {
            urlPattern: '$',
            selector: ".search-input",
            noShim: false,
            off: true,
            mode: "wordsQuery"
        },

        {
            urlPattern: '$',
            selector: ".dm-to-input",
            noShim: true,
            off: true,
            mode: "none"
        },
    ]
  },
  "origin-https://www.facebook.com": {
    "defaultFingerprint": "0235909f3873546ad90d439679339ecec80ed8ebc4adcdd9420775fba16a9bd1",
    "keys": {
      "0235909f3873546ad90d439679339ecec80ed8ebc4adcdd9420775fba16a9bd1": {
        "color": 6,
        "name": "ShadowCrypt Users",
        "note": "ShadowCrypt comes with this key. Anyone can get it.",
        "passphrase": "wide open",
        "secret": [
          2200342711,
          1762975859,
          1997565962,
          416743212
        ]
      }
    },
    "rules": [
        {
            urlPattern: '$',
            selector: "#email",
            noShim: true, 
            off: true,
            mode: "none"
        },

        {
            urlPattern: '$',
            selector: "#pass",
            noShim: true,
        },

        {
            urlPattern: '$',
            selector: ".inputtext.DOMControl_placeholder.hidden_elem",
            noShim: false,
            off: true,
            mode: "wordsQuery"
        },

        {
            urlPattern: '$',
            selector: ".inputtext.DOMControl_placeholder",
            noShim: true,
        },

        {
            urlPattern: '$',
            selector: ".inputtext.inputsearch.textInput",
            off: true,
            mode: "wordsQuery"
        },

        {
            urlPattern: '$',
            selector: ".inputtext.inputsearch",
            off: true,
            mode: "wordsQuery"
        },

        {
            urlPattern: '$',
            selector: "#u_0_1",
            noShim: true
        },

        {
            urlPattern: '$',
            selector: "#u_0_a",
            noShim: true
        },

        {
            urlPattern: '$',
            selector: "#u_0_3",
            noShim: true
        },

        {
            urlPattern: '$',
            selector: "#u_0_5",
            noShim: true
        },

        {
            urlPattern: '$',
            selector: "#u_0_8",
            noShim: true
        },
    ]
  }
}
		);
	}
});
