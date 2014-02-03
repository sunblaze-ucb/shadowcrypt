// this is sjcl configured with:
// --compress=yui --without-all --with-bitArray --with-codecString --with-codecHex --with-sha256
var sjcl={cipher:{},hash:{},keyexchange:{},mode:{},misc:{},codec:{},exception:{corrupt:function(a){this.toString=function(){return"CORRUPT: "+this.message};this.message=a},invalid:function(a){this.toString=function(){return"INVALID: "+this.message};this.message=a},bug:function(a){this.toString=function(){return"BUG: "+this.message};this.message=a},notReady:function(a){this.toString=function(){return"NOT READY: "+this.message};this.message=a}}};sjcl.bitArray={bitSlice:function(b,c,d){b=sjcl.bitArray._shiftRight(b.slice(c/32),32-(c&31)).slice(1);return(d===undefined)?b:sjcl.bitArray.clamp(b,d-c)},extract:function(c,d,f){var b,e=Math.floor((-d-f)&31);if((d+f-1^d)&-32){b=(c[d/32|0]<<(32-e))^(c[d/32+1|0]>>>e)}else{b=c[d/32|0]>>>e}return b&((1<<f)-1)},concat:function(c,a){if(c.length===0||a.length===0){return c.concat(a)}var d,e,f=c[c.length-1],b=sjcl.bitArray.getPartial(f);if(b===32){return c.concat(a)}else{return sjcl.bitArray._shiftRight(a,b,f|0,c.slice(0,c.length-1))}},bitLength:function(d){var c=d.length,b;if(c===0){return 0}b=d[c-1];return(c-1)*32+sjcl.bitArray.getPartial(b)},clamp:function(d,b){if(d.length*32<b){return d}d=d.slice(0,Math.ceil(b/32));var c=d.length;b=b&31;if(c>0&&b){d[c-1]=sjcl.bitArray.partial(b,d[c-1]&2147483648>>(b-1),1)}return d},partial:function(b,a,c){if(b===32){return a}return(c?a|0:a<<(32-b))+b*0x10000000000},getPartial:function(a){return Math.round(a/0x10000000000)||32},equal:function(e,d){if(sjcl.bitArray.bitLength(e)!==sjcl.bitArray.bitLength(d)){return false}var c=0,f;for(f=0;f<e.length;f++){c|=e[f]^d[f]}return(c===0)},_shiftRight:function(d,c,h,f){var g,b=0,e;if(f===undefined){f=[]}for(;c>=32;c-=32){f.push(h);h=0}if(c===0){return f.concat(d)}for(g=0;g<d.length;g++){f.push(h|d[g]>>>c);h=d[g]<<(32-c)}b=d.length?d[d.length-1]:0;e=sjcl.bitArray.getPartial(b);f.push(sjcl.bitArray.partial(c+e&31,(c+e>32)?h:f.pop(),1));return f},_xor4:function(a,b){return[a[0]^b[0],a[1]^b[1],a[2]^b[2],a[3]^b[3]]}};sjcl.codec.utf8String={fromBits:function(a){var b="",e=sjcl.bitArray.bitLength(a),d,c;for(d=0;d<e/8;d++){if((d&3)===0){c=a[d/4]}b+=String.fromCharCode(c>>>24);c<<=8}return decodeURIComponent(escape(b))},toBits:function(d){d=unescape(encodeURIComponent(d));var a=[],c,b=0;for(c=0;c<d.length;c++){b=b<<8|d.charCodeAt(c);if((c&3)===3){a.push(b);b=0}}if(c&3){a.push(sjcl.bitArray.partial(8*(c&3),b))}return a}};sjcl.codec.hex={fromBits:function(b){var c="",d,a;for(d=0;d<b.length;d++){c+=((b[d]|0)+0xf00000000000).toString(16).substr(4)}return c.substr(0,sjcl.bitArray.bitLength(b)/4)},toBits:function(d){var c,b=[],a;d=d.replace(/\s|0x/g,"");a=d.length;d=d+"00000000";for(c=0;c<d.length;c+=8){b.push(parseInt(d.substr(c,8),16)^0)}return sjcl.bitArray.clamp(b,a*4)}};sjcl.hash.sha256=function(a){if(!this._key[0]){this._precompute()}if(a){this._h=a._h.slice(0);this._buffer=a._buffer.slice(0);this._length=a._length}else{this.reset()}};sjcl.hash.sha256.hash=function(a){return(new sjcl.hash.sha256()).update(a).finalize()};sjcl.hash.sha256.prototype={blockSize:512,reset:function(){this._h=this._init.slice(0);this._buffer=[];this._length=0;return this},update:function(f){if(typeof f==="string"){f=sjcl.codec.utf8String.toBits(f)}var e,a=this._buffer=sjcl.bitArray.concat(this._buffer,f),d=this._length,c=this._length=d+sjcl.bitArray.bitLength(f);for(e=512+d&-512;e<=c;e+=512){this._block(a.splice(0,16))}return this},finalize:function(){var c,a=this._buffer,d=this._h;a=sjcl.bitArray.concat(a,[sjcl.bitArray.partial(1,1)]);for(c=a.length+2;c&15;c++){a.push(0)}a.push(Math.floor(this._length/0x100000000));a.push(this._length|0);while(a.length){this._block(a.splice(0,16))}this.reset();return d},_init:[],_key:[],_precompute:function(){var d=0,c=2,b;function a(e){return(e-Math.floor(e))*0x100000000|0}outer:for(;d<64;c++){for(b=2;b*b<=c;b++){if(c%b===0){continue outer}}if(d<8){this._init[d]=a(Math.pow(c,1/2))}this._key[d]=a(Math.pow(c,1/3));d++}},_block:function(q){var e,f,t,s,u=q.slice(0),j=this._h,c=this._key,r=j[0],p=j[1],o=j[2],n=j[3],m=j[4],l=j[5],g=j[6],d=j[7];for(e=0;e<64;e++){if(e<16){f=u[e]}else{t=u[(e+1)&15];s=u[(e+14)&15];f=u[e&15]=((t>>>7^t>>>18^t>>>3^t<<25^t<<14)+(s>>>17^s>>>19^s>>>10^s<<15^s<<13)+u[e&15]+u[(e+9)&15])|0}f=(f+d+(m>>>6^m>>>11^m>>>25^m<<26^m<<21^m<<7)+(g^m&(l^g))+c[e]);d=g;g=l;l=m;m=n+f|0;n=o;o=p;p=r;r=(f+((p&o)^(n&(p^o)))+(p>>>2^p>>>13^p>>>22^p<<30^p<<19^p<<10))|0}j[0]=j[0]+r|0;j[1]=j[1]+p|0;j[2]=j[2]+o|0;j[3]=j[3]+n|0;j[4]=j[4]+m|0;j[5]=j[5]+l|0;j[6]=j[6]+g|0;j[7]=j[7]+d|0}};


shadowCrypt = {};
shadowCrypt.KeyManagement = new function () {

    // Modal UI helpers
    var dialogCallback;
    var keyDialogCallback;
    var keyDialogDeleteCallback;

    // Generic function to display a modal element
    function displayModal(elementSelector, fadeOut) {

        var element = $(elementSelector);
        var modal = element.parents(".modal");

        modal.add(element).addClass("displayed");

        if (fadeOut === undefined) fadeOut = true;

        if (fadeOut) {
            modal.addClass("fade-out");
        } else {
            modal.removeClass("fade-out");
        }
    }

    // Generic function to hide a modal element
    function hideModal(modal) {
        var displayedElements = modal.children(".displayed");
        modal.add(displayedElements).removeClass("displayed");
    }


    // Displaying the normal dialogs
    function displayOKCancelDialog(content, callback) {
        dialogCallback = callback;

        $("#ok-cancel-dialog").find(".dialog-content").html(content);

        displayModal("#ok-cancel-dialog");
    }

    function displayCloseDialog(content) {

        $("#close-dialog").find(".dialog-content").html(content);

        displayModal("#close-dialog");
    }

    function hideDialog() {
        hideModal($("#dialog-box"));
    }

    // Displaying the key dialog
    var activeDialogClass = null;
    function displayKeyDialog(dialogClass, callback, deleteCallback) {
        keyDialogCallback = callback;
        keyDialogDeleteCallback = deleteCallback;

        var dialog = $("#key-dialog");

        if (activeDialogClass) {
            dialog.removeClass(activeDialogClass);
        }

        activeDialogClass = dialogClass;

        dialog.addClass(activeDialogClass);

        displayModal("#key-dialog");
    }

    function hideKeyDialog() {
        hideModal($("#key-dialog-modal"));
    }


    // Key icon color.
    var activeEditKeyColor = 0;

    function changeEditKeyColor(newColor) {
        var keyIcon = $("#edit-key-title").find(".shadowcrypt-key");
        keyIcon.removeClass("shadowcrypt-color-" + activeEditKeyColor);
        activeEditKeyColor = newColor;
        keyIcon.addClass("shadowcrypt-color-" + activeEditKeyColor);
    }

    function resetEditKeyColor(newColor) {
        changeEditKeyColor(newColor);
        $("#key-dialog-color" + activeEditKeyColor).prop("checked", true);
    }

    // Callback for when something is changed in the edit key dialog.
    var onKeyChangeCallback;


    // Key Management Main Initialize

    this.initialize = function (domains, newKeyCallback, editKeyCallback, deleteKeyCallback, exportKeyFunction, importKeyFunction, defaultChangedCallback) {

        // Populate the table of keys.
        var keysTable =  $("#domain-list").find(".keys-table");
        var globalHoverCounter = 0;
        var tooltipActive = false;

        function createKeyUI(domain, key, defaultKey, url){
            var keyButton = $("<div class='key-holder" + (defaultKey ? " default-key" : "") +
                "'><div class='shadowcrypt-key shadowcrypt-color-" + key.color +
                "'></div><div class='key-name-wrapper'><div class='shadowcrypt-key-name shadowcrypt-color-" + key.color +
            "'>" + key.name + "</div></div></div>");

        // Edit key button.
        keyButton.click(function(){
            $("#edit-key-domain").text(url);

            $("#key-dialog-name").val(key.name);

            $("#key-dialog-note").val(key.note);

            $("#key-dialog-default").prop("checked", domain.default == domain.keys.indexOf(key));

            $("#key-dialog-export").text(exportKeyFunction(domain.url, key));

            var keyCopy = jQuery.extend({}, key);
            onKeyChangeCallback = function() {
                keyCopy.name = $("#key-dialog-name").val();
                keyCopy.color = activeEditKeyColor;

                $("#key-dialog-export").text(exportKeyFunction(domain.url, keyCopy));
            };

            resetEditKeyColor(key.color);

            displayKeyDialog("edit-key", function() {

                // OK action at the end of edit key.
                var newName = $("#key-dialog-name").val();
                var newColor = activeEditKeyColor;
                var newNote = $("#key-dialog-note").val();
                var isDefault = $("#key-dialog-default").prop("checked");

                // Verify new data.
                if (!verifyKeyName(newName, domain, key)) {
                    return false;
                }

                // Update the UI.
                var label = keyButton.find(".shadowcrypt-key-name");
                keyButton.find(".shadowcrypt-key").add(label).removeClass("shadowcrypt-color-" + key.color).addClass("shadowcrypt-color-" + newColor);
                label.text(newName);

                if (isDefault) {
                    changeDefaultKey(domain, key);
                }

                // Update the object.
                key.name = newName;
                key.color = newColor;
                key.note = newNote;

                // Report to callback.
                editKeyCallback(url, key);

                // Return true if everything is OK and dialog should close.
                return true;
            }, function(deletedCallback){
                // Delete key action.
                var name = $("#key-dialog-name").val();
                displayOKCancelDialog("<p>Delete key " + name + "?</p>", function(){
                    deleteKey(domain, key, url);
                    hideKeyDialog();
                });
            });
        });

        var hover = false;

        keyButton.hover(function(){
            hover=true;
            globalHoverCounter++;
            setTimeout(function(){
                if (hover) {
                    keysTable.addClass("tooltip-active");
                }
            }, 1000);
        }, function(){
            hover=false;
            globalHoverCounter--;
            setTimeout(function(){
                if (globalHoverCounter == 0 ) {
                    keysTable.removeClass("tooltip-active");
                }
            }, 200);
        });

        domain.keysHolder.append(keyButton);
        }

        function createDomainUI(domain, url){

            // Create domain editor row.
            var protocolIndex = url.indexOf("://");
                if (protocolIndex > -1) {
                    protocolIndex += 3;
                } else {
                    protocolIndex = 0;
                }

                var displayName = url.substr(protocolIndex);
                var row = $("<tr><td class='domain-name'>" + displayName + "</td></tr>");
                domain.row = row;

                // Create keys cell.
                var keysCell = $("<td>");

                // Delete button
                var deleteButton = $("<div class='delete-button'>");
                deleteButton.click(function() {
                    displayOKCancelDialog("<p>Delete all the keys for domain " + displayName + "?</p>", function(){
                        var keys = $.extend({}, domain.keys);
                        for (var key in keys) {
                            deleteKey(domain, key, url);
                        }
                    });
                });
                keysCell.append(deleteButton);

                // Create keys holder.
                var keysHolder = $("<div>");
                keysCell.append(keysHolder);
                row.append(keysCell);
                domain.keysHolder = keysHolder;

                for (var key in domain.keys) {
                    createKeyUI(domain, key, false, url);
                }

                // Insert row.
                keysTable.append(row);
        }

        for (var origin in domains) {
            createDomainUI(domains[origin], origin);
        };

        // Helper for updating the UI with a new key
        function addNewKeyUI(url, key, fingerprint) {
            // Is this an existing domain?
            // Add the key to the database and create the UI.
            url = 'origin-' + url;
            var domain = domains[url];
            console.log('domain: ', url, domain, domains);

            if (domain) {
                // Verify data.
                if (!verifyKeyName(key.name, domain, null)) {
                    return false;
                }
                domain.keys[fingerprint] = key;
                createKeyUI(domain, key, url);
            } else {
                domain = {
                    url: url,
                    keys: {},
                    "default": 0
                };
                domain.keys[fingerprint] = key;
                domains[url] = domain;
                console.log(domains);
                createDomainUI(domain, url);
            }

            var newDomain = {};
            newDomain[url] = domain;
            chrome.storage.sync.set(newDomain);
            changeDefaultKey(domain, key);

            // Return true if key was added OK.
            return true;
        }

        // Helper for deleting a key from the UI
        function deleteKey(domain, key, url) {
            delete domain.keys[key];
            var newData = {};
            newData[url] = domain
            chrome.storage.sync.set(newData, function () {
                console.log(domain.keysHolder.find(".key-holder"));
                domain.keysHolder.find(".key-holder")[keyIndex].remove();
                // If the domain is empty, remove it.
                if ($.isEmptyObject(domain.keys)) {
                    domain.row.remove();
                    chrome.storage.sync.remove(url);
                    for (var site in domains) {
                        if ($.isEmptyObject(domains[site].keys)) {
                            delete domains[site];
                        }
                    }
                } else {
                    // Make sure to reassign the default if needed.
                    if (domain.default == keyIndex) {
                        // Default was deleted, reassign to the end.
                        changeDefaultKey(domain, domain.keys[domain.keys.length-1]);
                    } else if (domain.default > keyIndex) {
                        // Key was removed in front of default, so default needs to be reassigned.
                        domain.default--;
                    }
                }

                // Report to callback.
                deleteKeyCallback(domain, key);
            });
        }

        // Helper for making sure the key name is unique
        function verifyKeyName(name, domain, existing) {
            var nameOK = true;

            for (key in domain.keys) {
                if (key.name == name && key != existing) {
                    displayCloseDialog("<p>The name " + name + " is already in use for " + domain.url +". Please choose another key name.</p>");
                    nameOK = false;
                }
            }

            return nameOK;
        }

        // Helper for changing the default key of the domain
        function changeDefaultKey(domain, key) {
            var oldDefault = domain.default;

            // Remove old default key.
            domain.keysHolder.find(".key-holder").eq(domain.default).removeClass("default-key");

            // Add new one.
            var keyIndex = domain.keys.indexOf(key);
            domain.default = keyIndex;
            domain.keysHolder.find(".key-holder").eq(domain.default).addClass("default-key");

            // Report to callack if default has changed.
            if (domain.default != oldDefault) {
                defaultChangedCallback(domain, key);
            }
        }


        // Hook up the main toolbar buttons.

        // New key
        $("#new-key-button").click(function(){

            var url = "",
                secret = Array.prototype.slice.call(window.crypto.getRandomValues(new Uint32Array(4))),
                fingerprint = sjcl.codec.hex.fromBits(sjcl.hash.sha256(secret)),
                key = {
                    name: "Default",
                    color: Math.floor(Math.random() * 7),
                    note: "",
                    passphrase: "holder holder",
                    secret: secret,
                };

            $("#key-dialog-url").val(url);

            $("#key-dialog-name").val(key.name);

            $("#key-dialog-note").val(key.note);

            $("#key-dialog-default").prop("checked", true);

            $("#key-dialog-export").text(exportKeyFunction(url, key));

            onKeyChangeCallback = function() {
                key.name = $("#key-dialog-name").val();
                key.color = activeEditKeyColor;
                url = $("#key-dialog-url").val();

                $("#key-dialog-export").text(exportKeyFunction(url, key));
            };

            resetEditKeyColor(key.color);

            displayKeyDialog("new-key", function(){
                // OK action at the end of add new key.
                onKeyChangeCallback();

                // Report to callback. We might get a new object.
                key = newKeyCallback(url, key);

                // Update the UI.
                var success = addNewKeyUI(url, key, fingerprint);
                if (!success) {
                    return false;
                }

                // Return true if everything is OK and dialog should close.
                return true;
            });
        });

        // Import key
        // TODO
        $("#import-key-button").click(function(){
            $("#key-dialog-import").val("");

            displayKeyDialog("import-key", function(){
                var string = $("#key-dialog-import").val();

                var entry = importKeyFunction(string);

                addNewKeyUI(entry.url, entry.key);
            });
        });

        // Hook up dialog buttons.
        $("#key-dialog-delete").click(function(){
            var deleted = false;
            if (keyDialogDeleteCallback) {
                keyDialogDeleteCallback();
            }

            return false;
        });

        $("#key-dialog-cancel").click(function(){
            hideKeyDialog();

            return false;
        });

        function keyDialogConfirmed(){
            var success = true;
            if (keyDialogCallback) {
                success = keyDialogCallback();
            }

            if (success) hideKeyDialog();

            return false;
        }

        $("#key-dialog-ok").click(keyDialogConfirmed);
        $("#key-dialog").submit(keyDialogConfirmed);

        $("#dialog-cancel").add("#dialog-close").click(hideDialog);
        $("#dialog-ok").click(function(){
            if (dialogCallback) {
                dialogCallback();
                dialogCallback = null;
            }

            hideDialog();
        });


        // Hook up color selection buttons.
        for (var i=0;i<7;i++) {
            (function(i){
                $("#key-dialog-color" + i).click(function(){
                    changeEditKeyColor(i);
                    onKeyChangeCallback();
                });})(i);
        }

        // Hook up input box changes.
        $("#key-dialog-name").add("#key-dialog-url").change(function(){
            onKeyChangeCallback();
        });

        $("#key-dialog-name").add("#key-dialog-url").keyup(function(){
            onKeyChangeCallback();
        });
    };

};


// On load initialize the UI
$(function () {
    chrome.storage.sync.get(function (domains) {
        shadowCrypt.KeyManagement.initialize( 
            domains
            , function(url, newKey){
                // This is a callback function when a new key is created.
                console.log("Key " + newKey.name + " created for URL " + url);

                // You can return a new object if you want that to be stored internally
                // and returned as the argument of the edit key callback.
                return newKey;

            }, function(domain, editedKey){
                // This is a callback function when a key has been updated.
                console.log("Key " + editedKey.name + " at URL " + domain + " was edited.");

            }, function(domain, deletedKey){
                // This is a callback function when a key is deleted.
                console.log("Key " + deletedKey.name + " deleted for URL " + domain.url);

            }, function(domain, key){
                // This is a function that transforms a key object into an export string.
                return domain + " [" + key.name + "] " + key.key;

            }, function(string){
                // This is a function that transforms a key string into a key object.
                var parts = string.split(" ");
                var domain = parts[0];
                var name = parts[1].substr(1, parts[1].length-2);
                var key = parts[2];
                return {
                    url: domain,
                    key: {
                        name: name,
                        color: Math.floor(Math.random() * 7),
                        key: key
                    }
                };
            }, function(domain, defaultKey) {
                // This is a callback function when a default key was changed for a domain.
                console.log("Key " + defaultKey.name + " is now the default for URL " + domain + ".");
            });
    });
});
