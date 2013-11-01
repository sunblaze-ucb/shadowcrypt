var content = function () {
	var incoming = null;
	window.addEventListener('zerokit-prop-response', function (e) {
		incoming = e.detail.value;
	});
	window.zerokitDefaultAccessor = function (prop) {
		return {
			get: function () {
				var add = !document.contains(this);
				if (add) document.documentElement.appendChild(this);
				var e = new CustomEvent('zerokit-prop-get', {detail: {prop: prop}});
				this.dispatchEvent(e);
				var value = incoming;
				incoming = null;
				if (add) document.documentElement.removeChild(this);
				return value;
			},
			set: function (v) {
				var add = !document.contains(this);
				if (add) document.documentElement.appendChild(this);
				e = new CustomEvent('zerokit-prop-set', {detail: {prop: prop, value: v}});
				this.dispatchEvent(e);
				if (add) document.documentElement.removeChild(this);
			}
		}
	};
};

window.addEventListener('zerokit-prop-get', function (e) {
	e.stopPropagation();
	var value = e.target[e.detail.prop];
	var f = new CustomEvent('zerokit-prop-response', {detail: {value: value}});
	window.dispatchEvent(f);
}, true);

window.addEventListener('zerokit-prop-set', function (e) {
	e.stopPropagation();
	e.target[e.detail.prop] = e.detail.value;
}, true);

var o = document.createElement('script');
o.textContent = '(' + content + ')()';
document.documentElement.appendChild(o);
