function setupFormValidation(form, url, callback) {
  var idleTime = 250,
      oldValue,
      inFlightXHR,
      timeoutId;

  function timerFunction() {
    console.log("timerFunction!");

    timeoutId = undefined;
    inFlightXHR = $.ajax({
      type: 'POST',
      url: url,
      data: oldValue,
      dataType: 'json',
      error: xhrCallback,
      success: xhrCallback
    });
  }

  function xhrCallback(data, textStatus) {
    console.log("xhr done: ", data, textStatus);

    if (textStatus == 'success') {
      console.log("plan success");
      return callback('success', data);
    }

    var status = 0;
    try {
      status = data.status; // can raise exception on IE sometimes
    } catch (e) {
      // ignore
    }
    if (status >= 200 && status < 300 && data.responseText === '') {
      console.log("inplain success");
      return callback('success');
    }

    if (status != 400 || textStatus != 'error') {
      return; // onUnexpectedXHRError(data);
    }

    console.log("plain error");
    var errorsData = $.httpData(data, null, this);
    callback('error', errorsData);
  }

  function cancelXHR() {
    if (inFlightXHR) {
      Abortarium.abortRequest(inFlightXHR);
      inFlightXHR = null;
    }
  }

  var firstTime = true;

  function onPotentialChanges() {
    if (paused) {
      return;
    }

    var newValue = serializeForm(form);
    if (newValue == oldValue) {
      return;
    }
    oldValue = newValue;

    var wasFirstTime = firstTime;
    firstTime = false;

    if (timeoutId) {
      console.log("aborting next validation");
      clearTimeout(timeoutId);
    }
    timeoutId = setTimeout(timerFunction, idleTime);
    cancelXHR();

    if (wasFirstTime) {
      cancelTimeout();
      timerFunction();
    }
  }

  function cancelTimeout() {
    if (timeoutId) {
      clearTimeout(timeoutId);
      timeoutId = null;
    }
  }

  var observer = form.observePotentialChanges(onPotentialChanges),
      paused = false;

  return {
    abort: function () {
      cancelTimeout();
      cancelXHR();
      observer.stopObserving();
    },
    pause: function () {
      if (paused) {
        return;
      }
      paused = true;
      cancelXHR();
      cancelTimeout();
    },
    unpause: function () {
      paused = false;
      onPotentialChanges();
    }
  };
}

var BucketDetailsDialog = mkClass({
  initialize: function (initValues, isNew, options) {
    this.isNew = isNew;
    this.initValues = initValues;
    initValues.ramQuotaMB = Math.floor(initValues.quota.rawRAM / 1048576);

    options = options || {};

    this.dialogID = options.id || 'bucket_details_dialog';

    this.onSuccess = options.onSuccess || function () {
      hideDialog(this.dialogID);
    };

    this.refreshBuckets = options.refreshBuckets || $m(BucketsSection, 'refreshBuckets');

    var dialog = this.dialog = $('#' + this.dialogID);

    dialog.removeClass('editing').removeClass('creating');
    dialog.addClass(isNew ? 'creating' : 'editing');

    dialog.find('[name=name]').boolAttr('disabled', !isNew);

    dialog.find('[name=replicaNumber]').boolAttr('disabled', !isNew);
    dialog.find('.for-enable-replication input').boolAttr('disabled', !isNew);

    dialog.find('[name=ramQuotaMB]').boolAttr('disabled', !isNew && (initValues.bucketType == 'memcached'));

    var oldBucketType;
    dialog.observePotentialChanges(function () {
      var newType = dialog.find('[name=bucketType]:checked').attr('value');
      if (newType == oldBucketType) {
        return;
      }
      oldBucketType = newType;
      var isPersistent = (newType == 'membase');
      dialog.find('.persistent-only')[isPersistent ? 'slideDown' : 'slideUp']('fast');
      dialog[isPersistent ? 'removeClass' : 'addClass']('bucket-is-non-persistent');
      dialog[isPersistent ? 'addClass' : 'removeClass']('bucket-is-persistent');

      if (errorsCell.value && errorsCell.value.summaries) {
        errorsCell.setValueAttr(null, 'summaries', 'ramSummary');
      }
    });

    var oldReplicationEnabled;
    dialog.observePotentialChanges(function () {
      var replicationEnabled = !!(dialog.find('.for-enable-replication input').attr('checked'));
      if (replicationEnabled === oldReplicationEnabled) {
        return;
      }
      oldReplicationEnabled = replicationEnabled;
      dialog.find('.for-replica-number')[replicationEnabled ? 'show' : 'hide']();
      dialog.find('.hidden-replica-number').need(1).boolAttr('disabled', replicationEnabled);
      if (isNew) {
        dialog.find('.for-replica-number select').need(1).boolAttr('disabled', !replicationEnabled);
      }
    });

    var preDefaultAuthType;
    function nameObserver(value) {
      var forAsciiRadio = dialog.find('.for-ascii input'),
          forSASLRadio = dialog.find('.for-sasl-password input'),
          isDefault = (value == "default");

      dialog[isDefault ? 'addClass' : 'removeClass']('bucket-is-default');
      if (isDefault) {
        preDefaultAuthType = (forAsciiRadio.filter(':checked').length) ? '.for-ascii' : '.for-sasl-password';
        forAsciiRadio.boolAttr('disabled', true);
        forAsciiRadio.boolAttr('checked', false);
        forSASLRadio.boolAttr('checked', true);
      } else {
        forAsciiRadio.boolAttr('disabled', false);
        if (preDefaultAuthType) {
          var isAscii = (preDefaultAuthType == '.for-ascii');
          forAsciiRadio.boolAttr('checked', isAscii);
          forSASLRadio.boolAttr('checked', !isAscii);
        }
      }
    }

    dialog.find('[name=name]').observeInput(nameObserver);
    nameObserver(dialog.find('[name=name]').val());

    this.cleanups = [];

    var errorsCell = this.errorsCell = new Cell();
    errorsCell.subscribeValue($m(this, 'onValidationResult'));
    this.formValidator = setupFormValidation(dialog.find('form'),
                                             this.initValues.uri + '?just_validate=1',
                                             function (status, errors) {
                                               console.log("setting errors: ", errors);
                                               errorsCell.setValue(errors);
                                             });

    this.cleanups.push($m(this.formValidator, 'abort'));
  },

  bindWithCleanup: function (jq, event, callback) {
    jq.bind(event, callback);
    return function () {
      jq.unbind(event, callback);
    };
  },

  submit: function () {
    var self = this,
        closeCleanup = self.bindWithCleanup(self.dialog.find('.jqmClose'),
                                            'click',
                                            function (e) {
                                              e.preventDefault();
                                              e.stopPropagation();
                                            });
    self.needBucketsRefresh = true;

    var nonPersistent = null;
    if (self.dialog.find('[name=bucketType]:checked').val() != 'membase') {
      self.dialog.find('.persistent-only input')
        .filter(':not([disabled])')
        .boolAttr('disabled', true);
    }

    self.formValidator.pause();

    postWithValidationErrors(self.initValues.uri, self.dialog.find('form'), function (data, status) {
      if (status == 'success') {
        self.refreshBuckets(function () {
          self.needBucketsRefresh = false;
          enableForm();
          self.onSuccess();
        });
        return;
      }

      enableForm();

      var errors = data[0]; // we expect errors as a hash in this case
      self.errorsCell.setValue(errors);
      if (errors._) {
        self.dialog.addClass("overlayed");
        genericDialog({buttons: {ok: true},
                       header: "Failed To Create Bucket",
                       text: errors._,
                       callback: function (e, btn, dialog) {
                         dialog.close();
                         self.dialog.removeClass("overlayed");
                       }
                      });
      }
    });

    if (nonPersistent) {
      nonPersistent.boolAttr('disabled', false);
    }

    var toDisable = self.dialog.find('input[type=text], input:not([type]), input[type=checkbox]')
      .filter(':not([disabled])')
      .add(self.dialog.find('button'));

    // we need to disable after post is sent, 'cause disabled inputs are not sent
    toDisable.add(self.dialog).css('cursor', 'wait').boolAttr('disabled', true);

    function enableForm() {
      self.formValidator.unpause();
      closeCleanup();
      toDisable.boolAttr('disabled', false)
        .add(self.dialog).css('cursor', 'auto');
    }
  },
  startForm: function () {
    var self = this,
        form = this.dialog.find('form');

    setFormValues(form, self.initValues);

    form.find('[name=bucketType]').boolAttr('disabled', !self.isNew);
    form.find('.for-enable-replication input').boolAttr('checked', self.initValues.replicaNumber !== 0);

    self.cleanups.push(self.bindWithCleanup(form, 'submit', function (e) {
      e.preventDefault();
      self.submit();
    }));
  },
  startDialog: function () {
    var self = this;

    self.startForm();

    showDialog(this.dialogID, {
      onHide: function () {
        self.cleanup();
        if (self.needBucketsRefresh) {
          DAL.cells.currentPoolDetails.setValue(undefined);
          DAL.cells.currentPoolDetails.invalidate();
        }
      }
    });
  },
  cleanup: function () {
    _.each(this.cleanups, function (c) {
      c();
    });
  },

  renderGauge: function (jq, total, thisBucket, otherBuckets) {
    var thisValue = thisBucket,
        formattedBucket = ViewHelpers.formatQuantity(thisBucket, null, null, ' ');

    if (_.isString(thisValue)) {
      formattedBucket = thisValue;
      thisValue = 0;
    }

    var options = {
      topAttrs: {'class': 'size-gauge for-ram'},
      topRight: ['Cluster quota', ViewHelpers.formatMemSize(total)],
      items: [
        {name: 'Other Buckets',
         value: otherBuckets,
         attrs: {style: 'background-position: 0 -15px;'},
         tdAttrs: {style: 'color:blue;'}},
        {name: 'This Bucket',
         value: thisValue,
         attrs: {style: 'background-position: 0 -45px;'},
         tdAttrs: {style: 'color:green;'}},
        {name: 'Free',
         value: total - otherBuckets - thisValue,
         tdAttrs: {style: 'color:#444245;'}}
      ],
      markers: []
    };

    if (options.items[2].value < 0) {
      options.items[1].value = total - otherBuckets;
      options.items[2] = {
        name: 'Overcommitted',
        value: otherBuckets + thisValue - total,
        attrs: {style: 'background-position: 0 -60px;'},
        tdAttrs: {style: 'color:#e43a1b;'}
      };
      options.markers.push({value: total,
                            attrs: {style: 'background-color:#444245;'}});
      options.markers.push({value: otherBuckets + thisValue,
                            attrs: {style: 'background-color:red;'}});
      options.topLeft = ['Total Allocated', ViewHelpers.formatMemSize(otherBuckets + thisValue)];
      options.topLeftAttrs = {style: 'color:#e43a1b;'};
    }

    jq.replaceWith(memorySizesGaugeHTML(options));
  },

  renderError: function (field, error) {
    this.dialog.find('.error-container.err-' + field).text(error || '')[error ? 'addClass' : 'removeClass']('active');
    this.dialog.find('[name=' + field + ']')[error ? 'addClass' : 'removeClass']('invalid');
  },

  // this updates our gauges and errors
  // we don't use it to set input values, 'cause for the later we need to do it once
  onValidationResult: function (result) {
    result = result || {};
    // if (!result)                // TODO: handle it
    //   return;
    var self = this,
        summaries = result.summaries || {},
        ramSummary = summaries.ramSummary,
        ramGauge = self.dialog.find(".size-gauge.for-ram"),
        memcachedSummaryJQ = self.dialog.find('.memcached-summary'),
        memcachedSummaryVisible = ramSummary && ramSummary.perNodeMegs,
        knownFields = ('name ramQuotaMB replicaNumber proxyPort').split(' '),
        errors = result.errors || {};

    if (ramSummary) {
      self.renderGauge(ramGauge,
                       ramSummary.total,
                       ramSummary.thisAlloc,
                       ramSummary.otherBuckets);
    }
    ramGauge.css('visibility', ramSummary ? 'visible' : 'hidden');

    if (memcachedSummaryVisible) {
      memcachedSummaryJQ.text('Total bucket size = '
                              + Math.floor(ramSummary.thisAlloc / 1048576)
                              + ' MB ('
                              + ramSummary.perNodeMegs
                              + ' MB x ' + ViewHelpers.count(ramSummary.nodesCount, 'node') +')');
    }
    memcachedSummaryJQ.css('display', memcachedSummaryVisible ? 'block' : 'none');

    _.each(knownFields, function (name) {
      self.renderError(name, errors[name]);
    });
  }
});

var BucketsSection = {
  renderRAMDetailsGauge: function (e, details) {
    var poolDetails = DAL.cells.currentPoolDetails.value;
    BucketDetailsDialog.prototype.renderGauge($(e).find('.for-ram'),
                                              poolDetails.storageTotals.ram.quotaTotal,
                                              details.quota.ram,
                                              poolDetails.storageTotals.ram.quotaUsed - details.quota.ram);
  },

  renderDiskGauge: function (jq, total, thisBucket, otherBuckets, otherData) {
    var formattedBucket = ViewHelpers.formatQuantity(thisBucket, null, null, ' '),
        free = total - otherData - thisBucket - otherBuckets,
        options = {
                    topAttrs: {'class': 'size-gauge for-hdd'},
                    topLeft: ['Other Data', ViewHelpers.formatMemSize(otherData)],
                    topRight: ['Total Cluster Storage', ViewHelpers.formatMemSize(total)],
                    items: [
                      {name: null,
                       value: otherData,
                       attrs: {style: 'background-position: 0 -30px;'}},
                      {name: 'Other Buckets',
                       value: otherBuckets,
                       attrs: {style: 'background-position: 0 -15px;'},
                       tdAttrs: {style: 'color:blue;'}},
                      {name: 'This Bucket',
                       value: thisBucket,
                       attrs: {style: 'background-position: 0 -45px;'},
                       tdAttrs: {style: 'color:green;'}},
                      {name: 'Free',
                       value: free,
                       tdAttrs: {style: 'color:#444245;'}}
                    ]
                  };

    jq.replaceWith(memorySizesGaugeHTML(options));
  },

  renderHDDDetailsGauge: function (e, details) {
    var jq = $(e).parent().find('.size-gauge.for-hdd'),
        poolDetails = DAL.cells.currentPoolDetails.value,
        hdd = poolDetails.storageTotals.hdd;
    BucketsSection.renderDiskGauge(jq,
                                   hdd.total,
                                   details.basicStats.diskUsed,
                                   hdd.usedByData - details.basicStats.diskUsed,
                                   hdd.used - hdd.usedByData);
  },
  init: function () {
    var self = this;
    var bucketsListCell = DAL.cells.bucketsListCell;

    self.settingsWidget = new MultiDrawersWidget({
      hashFragmentParam: "buckets",
      template: "bucket_settings",
      placeholderCSS: '#buckets .settings-placeholder',
      elementKey: 'name',
      actionLink: 'visitBucket',
      actionLinkCallback: function () {
        ThePage.ensureSection('buckets');
      },
      uriExtractor: function (item) {return item.uri;},
      valueTransformer: function (bucketInfo, bucketSettings) {
        var rv = _.extend({}, bucketInfo, bucketSettings);
        rv.storageInfoRelevant = (rv.bucketType == 'membase');
        return rv;
      },
      listCell: bucketsListCell
    });

    var stalenessCell = Cell.compute(function (v) {
      return v.need(bucketsListCell.ensureMetaCell()).stale;
    });

    renderCellTemplate(bucketsListCell, 'bucket_list', {
      beforeRendering: function () {
        self.settingsWidget.prepareDrawing();
      }, extraCells: [stalenessCell]
    });

    stalenessCell.subscribeValue(function (staleness) {
      if (staleness === undefined) {
        return;
      }
      var notice = $('#buckets .staleness-notice');
      notice[staleness ? 'show' : 'hide']();
      $('#manage_buckets_top_bar .create-bucket-button')[staleness ? 'hide' : 'show']();
    });

    $('.create-bucket-button').live('click', function (e) {
      e.preventDefault();
      BucketsSection.startCreate();
    });

    $('#bucket_details_dialog .delete_button').bind('click', function (e) {
      e.preventDefault();
      BucketsSection.startRemovingBucket();
    });
  },
  renderBucketDetails: function (item) {
    return this.settingsWidget.renderItemDetails(item);
  },
  refreshBuckets: function (callback) {
    return DAL.cells.bucketsListCell.refresh(callback);
  },
  withBucket: function (uri, body) {
    var value = DAL.cells.bucketsListCell.value;
    if (!value) {
      return;
    }
    var bucketInfo = _.detect(value, function (info) {
      return info.uri == uri;
    });

    if (!bucketInfo) {
      console.log("Not found bucket for uri:", uri);
      return null;
    }

    return body.call(this, bucketInfo);
  },
  findBucket: function (uri) {
    return this.withBucket(uri, function (r) {return r;});
  },
  showBucket: function (uri) {
    ThePage.ensureSection('buckets');
    // we don't care about value, but we care if it's defined
    DAL.cells.bucketsListCell.getValue(function (buckets) {
      var bucketDetails = _.detect(buckets, function (info) {return info.uri === uri;});
      if (!bucketDetails) {
        return;
      }
      BucketsSection.settingsWidget.detailsMap.getValue(function (mapValue) {
        var fullDetails = mapValue.get(bucketDetails);
        if (!fullDetails) {
          return;
        }
        BucketsSection.settingsWidget.openElement(bucketDetails.name);
        fullDetails.getValue(function (fullDetailsValue) {
          var initValues = _.extend({}, bucketDetails, fullDetailsValue);
          var dialog = new BucketDetailsDialog(initValues, false);

          BucketsSection.currentlyShownBucket = bucketDetails;
          dialog.startDialog();
        });
      });
    });
  },
  getPoolNodesCount: function () {
    return DAL.cells.currentPoolDetails.value.nodes.length;
  },
  onEnter: function () {
    this.refreshBuckets();
  },
  navClick: function () {
    this.onLeave();
    this.onEnter();
  },
  onLeave: function () {
    this.settingsWidget.reset();
  },
  startCreate: function () {
    var poolDetails = DAL.cells.currentPoolDetails.value,
        totals = poolDetails.storageTotals;

    if (totals.ram.quotaTotal == totals.ram.quotaUsed) {
      genericDialog({
        buttons: {ok: true},
        header: 'Cluster Memory Fully Allocated',
        text: 'All the RAM in the cluster is already allocated to existing buckets.\n\nDelete some buckets or change bucket sizes to make RAM available for additional buckets.'
      });
      return;
    }
    var initValues = {uri: '/pools/default/buckets',
                      bucketType: 'membase',
                      authType: 'sasl',
                      quota: {rawRAM: Math.floor((totals.ram.quotaTotal - totals.ram.quotaUsed) / poolDetails.nodes.length)},
                      replicaNumber: 1},
      dialog = new BucketDetailsDialog(initValues, true);

    dialog.startDialog();
  },
  startRemovingBucket: function () {
    if (!this.currentlyShownBucket) {
      return;
    }

    $('#bucket_details_dialog').addClass('overlayed');
    $('#bucket_remove_dialog .bucket_name').text(this.currentlyShownBucket.name);
    showDialog('bucket_remove_dialog', {
      onHide: function () {
        $('#bucket_details_dialog').removeClass('overlayed');
      }
    });
  },
  removeCurrentBucket: function () {
    // inner functions
    function ajaxCallback() {
      self.refreshBuckets(function() {
        spinner.remove();
        modal.finish();
        hideDialog('bucket_details_dialog');
        hideDialog('bucket_remove_dialog');
      });
    }

    var self = this,
        bucket = self.currentlyShownBucket;

    if (!bucket) {
      return;
    }

    var spinner = overlayWithSpinner('#bucket_remove_dialog'),
        modal = new ModalAction();

    $.ajax({
      type: 'DELETE',
      url: self.currentlyShownBucket.uri,
      success: ajaxCallback,
      errors: ajaxCallback
    });
    return;
  }
};

configureActionHashParam("editBucket", $m(BucketsSection, 'showBucket'));

$(function () {
  var oldIsSasl,
      dialog = $('#bucket_details_dialog');

  dialog.observePotentialChanges(function () {
    var saslSelected = $('#bucket_details_sasl_selected')[0];
    if (!saslSelected) { // might happen just before page unload
      return;
    }
    var isSasl = saslSelected.checked;
    if (oldIsSasl !== null && isSasl == oldIsSasl) {
      return;
    }
    oldIsSasl = isSasl;

    dialog.find('.for-sasl-password-input input').boolAttr('disabled', !isSasl);
    dialog.find('.for-proxy-port input').boolAttr('disabled', isSasl);
  });
});
