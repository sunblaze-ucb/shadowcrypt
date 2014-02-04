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

        function createKeyUI(domain, key, defaultKey, url) {
            var keyButton = $("<div class='key-holder" + (defaultKey ? " default-key" : "") +
                "'><div class='shadowcrypt-key shadowcrypt-color-" + key.color +
                "'></div><div class='key-name-wrapper'><div class='shadowcrypt-key-name shadowcrypt-color-" + key.color +
            "'>" + key.name + "</div></div></div>");

            // Edit key button.
            keyButton.click(function () {
                originLength = "origin-".length;
                $("#edit-key-domain").text(url.slice(originLength));

                $("#key-dialog-name").val(key.name);

                $("#key-dialog-note").val(key.note);

                for (var keyFingerprint in domain.keys) {
                    if (domain.keys[keyFingerprint] == key) break;
                }

                $("#key-dialog-default").prop("checked", domain.defaultFingerprint == keyFingerprint);

                $("#key-dialog-export").text(exportKeyFunction(url, key));

                var keyCopy = jQuery.extend({}, key);
                onKeyChangeCallback = function() {
                    keyCopy.name = $("#key-dialog-name").val();
                    keyCopy.color = activeEditKeyColor;
                    $("#key-dialog-export").text(exportKeyFunction(url, keyCopy));
                };

                resetEditKeyColor(key.color);

                displayKeyDialog("edit-key", function() {

                    // OK action at the end of edit key.
                    var newName = $("#key-dialog-name").val();
                    var newColor = activeEditKeyColor;
                    var newNote = $("#key-dialog-note").val();
                    var isDefault = $("#key-dialog-default").prop("checked");

                    // Verify new data.
                    if (!verifyKeyName(newName, domain, key, url)) {
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

                    var updateStorage = {};
                    updateStorage[url] = domain;


                    // Report to callback.
                    editKeyCallback(domain, key, url);

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
                        deleteKey(domain, keys[key], url);
                    }
                });
            });
            keysCell.append(deleteButton);

            // Create keys holder.
            var keysHolder = $("<div>");
            keysCell.append(keysHolder);
            row.append(keysCell);
            domain.keysHolder = keysHolder;

            for (var fingerprint in domain.keys) {
                var key = domain.keys[fingerprint];
                createKeyUI(domain, key, domain.defaultFingerprint == fingerprint, url);
            }

            // Insert row.
            keysTable.append(row);
        }

        for (var origin in domains) {
            createDomainUI(domains[origin], origin);
        };

        // Helper for updating the UI with a new key
        function addNewKeyUI(url, key, fingerprint, isDefault) {
            // Is this an existing domain?
            // Add the key to the database and create the UI.
            if (url.slice(0, "origin-".length) != "origin-") {
                url = 'origin-' + url;
            }
            var domain = domains[url];

            if (domain) {
                // Verify data.
                if (!verifyKeyName(key.name, domain, null, url)) {
                    return false;
                }
                domain.keys[fingerprint] = key;
                createKeyUI(domain, key, isDefault, url);
            } else {
                domain = {
                    keys: {},
                    "defaultFingerprint": fingerprint,
                    rules: []
                };
                domain.keys[fingerprint] = key;
                domains[url] = domain;
                createDomainUI(domain, url);
            }

            var newDomain = {};
            newDomain[url] = domain;

            newKeyCallback(domain, key, url);

            if (isDefault) {
                changeDefaultKey(domain, url);
            }

            // Return true if key was added OK.
            return true;
        }

        // Helper for deleting a key from the UI
        function deleteKey(domain, key, url) {
            var keys = Object.keys(domain.keys),
                eyIndex,
                isEmpty,
                fingerprint;

            for (var i = 0; i < keys.length; i++) {
                if (domain.keys[keys[i]] == key) {
                    fingerprint = keys[i];
                    keyIndex = i;
                    console.log(fingerprint);
                    break;
                }
            }

            delete domain.keys[fingerprint];

            domain.keysHolder.find(".key-holder")[keyIndex].remove();
            // If the domain is empty, remove it.
            if ($.isEmptyObject(domain.keys)) {
                domain.row.remove();
                for (var site in domains) {
                    if ($.isEmptyObject(domains[site].keys)) {
                        delete domains[site];
                        isEmpty = true;
                    }
                }
            } else {
                // Make sure to reassign the default if needed.
                if (domain.defaultFingerprint == fingerprint) {
                    // Default was deleted, reassign to the end.
                    var keys = Object.keys(domain.keys),
                        newDefault = keys[keys.length - 1];
                    changeDefaultKey(domain, domain.keys[newDefault]);
                }
            }

            // Report to callback.
            deleteKeyCallback(domain, key, url, isEmpty);
        }

        // Helper for making sure the key name is unique
        function verifyKeyName(name, domain, existing, url) {
            var nameOK = true;

            for (fingerprint in domain.keys) {
                var key = domain.keys[fingerprint];
                if (key.name == name && key != existing) {
                    displayCloseDialog("<p>The name " + name + " is already in use for " + url +". Please choose another key name.</p>");
                    nameOK = false;
                }
            }

            return nameOK;
        }

        // Helper for changing the default key of the domain
        function changeDefaultKey(domain, key) {
            var oldDefault = domain.defaultFingerprint;

            // Remove old default key.

            // Add new one.
            var index = 0,
                oldIndex = 0;

            for (var fingerprint in domain.keys) {
                if (fingerprint == oldDefault) break;
                oldIndex++;
            }

            //After loop, fingerprint is current key's fingerprint
            for (fingerprint in domain.keys) {
                if (domain.keys[fingerprint] == key) break;
                index++;
            }

            for (var url in domains) {
                if (domains[url] == domain) break;
            }

            domain.keysHolder.find(".key-holder").eq(oldIndex).removeClass("default-key");
            domain.defaultFingerprint = fingerprint;
            domain.keysHolder.find(".key-holder").eq(index).addClass("default-key");

            // Report to callack if default has changed.
            if (domain.defaultFingerprint != oldDefault) {
                defaultChangedCallback(domain, key, url);
            }
        }


        // Hook up the main toolbar buttons.

        // New key
        $("#new-key-button").click(function(){

            var url = "",
                secret = Array.prototype.slice.call(window.crypto.getRandomValues(new Uint32Array(4))),
                fingerprint = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(secret)),
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
                // Update the UI.
                var changeDefault = $("#key-dialog-default").prop("checked");
                var success = addNewKeyUI(url, key, fingerprint, changeDefault);
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

                debugger;
                var entry = importKeyFunction(string),
                    fingerprint = sjcl.hash.sha256.hash(entry.key.secret);

                addNewKeyUI(entry.url, entry.key, fingerprint, false)
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

function prepareSyncData(domain, url) {
    var newDoamin = {};
    newDoamin[url] = domain;
    return newDoamin;
}

function onNewKey(domain, key, url) {
    chrome.storage.sync.set(prepareSyncData(domain, url));
    console.log("Key " + key.name + " created for URL " + url);
    return key;
}

function onEditKey(domain, key, url) {
    chrome.storage.sync.set(prepareSyncData(domain, url));
    console.log("Key " + key.name + " at URL " + url + " was edited.");
}

function onDeletedKey(domain, key, url, isEmpty) {
    if (isEmpty) {
        chrome.storage.sync.remove(url);
    } else {
        chrome.storage.sync.set(prepareSyncData(domain, url));
    }
    console.log("Key " + key.name + " deleted for URL " + url);
};

function onDefaultChange(domain, key, url) {
    chrome.storage.sync.set(prepareSyncData(domain, url));
    console.log("Key " + key.name + " is now the default for URL " + url + ".");
}

// On load initialize the UI
$(function () {
    chrome.storage.sync.get(function (domains) {
        shadowCrypt.KeyManagement.initialize( 
            domains
            , onNewKey
            , onEditKey
            , onDeletedKey
            , function(url, key){
                // This is a function that transforms a key object into an export string.
                //TODO
                return url + " [" + key.name + "] " + sjcl.codec.hex.fromBits(key.secret);
            }, function(string){
                // This is a function that transforms a key string into a key object.
                var parts = string.split(" ");
                var url = parts[0];
                var name = parts[1].substr(1, parts[1].length-2);
                var secret = sjcl.codec.hex.toBits(parts[2]);
                return {
                    url: url,
                    key: {
                        name: name,
                        color: Math.floor(Math.random() * 7),
                        secret: secret,
                    }
                };
            }, onDefaultChange
        );
    });
});
