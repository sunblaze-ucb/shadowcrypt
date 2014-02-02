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

        function createKeyUI(domain, url, key, defaultKey){
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

                displayKeyDialog("edit-key", function(){

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
                        deleteKey(domain, key);
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
                        deleteKey(domain, key);
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
                createKeyUI(domain, key, false);
            }

            // Insert row.
            keysTable.append(row);
        }

        for (var origin in domains) {
            createDomainUI(domains[origin], origin);
        };

        // Helper for updating the UI with a new key
        function addNewKeyUI(url, key) {
            // Is this an existing domain?
            // Add the key to the database and create the UI.
            url = 'origin-' + url;
            var domain = domains[url];

            if (domain) {
                // Verify data.
                if (!verifyKeyName(key.name, domain, null)) {
                    return false;
                }

                domain.keys.push(key);
                createKeyUI(domain, key);
            } else {
                domain = {
                    url: url,
                    keys: [key],
                    "default": 0
                };
                domains[url] = (domain);
                createDomainUI(domain);
            }

            chrome.storage.sync.set({url: domain});
            changeDefaultKey(domain, key);

            // Return true if key was added OK.
            return true;
        }

        // Helper for deleting a key from the UI
        function deleteKey(domain, key) {
            delete domain.keys[key];
            domain.keysHolder.find(".key-holder")[keyIndex].remove();

            // If the domain is empty, remove it.
            if ($.isEmptyObject(domain.keys)) {
                domain.row.remove();
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

            var url = "";
            var key = {
                name: "Default",
        color: Math.floor(Math.random() * 7),
        note: "",
        key: "asdfoiasdfgoiawjgpwoj"
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
                var success = addNewKeyUI(url, key);
                if (!success) {
                    return false;
                }

                // Return true if everything is OK and dialog should close.
                return true;
            });
        });

        // Import key
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
