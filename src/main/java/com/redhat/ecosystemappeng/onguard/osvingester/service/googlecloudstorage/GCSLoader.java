/*
 * Copyright ${year} Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.redhat.ecosystemappeng.onguard.osvingester.service.googlecloudstorage;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.google.cloud.storage.Bucket;
import com.google.cloud.storage.Storage;
import com.redhat.ecosystemappeng.onguard.osvingester.model.IngestionReport;
import com.redhat.ecosystemappeng.onguard.osvingester.service.EcosystemLoader;
import com.redhat.ecosystemappeng.onguard.osvingester.service.VulnerabilityIngester;

import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.infrastructure.Infrastructure;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class GCSLoader implements EcosystemLoader {

  private static final Logger LOGGER = Logger.getLogger(GCSLoader.class);

  private final VulnerabilityIngester vulnerabilityIngester;
  private final Bucket bucket;
  private final ExecutorService executor = Executors.newFixedThreadPool(20);

  GCSLoader(Storage storage,
      @ConfigProperty(name = "import.osv-bucket", defaultValue = "osv-vulnerabilities") String osvBucketName,
      VulnerabilityIngester vulnerabilityIngester) {
    this.bucket = storage.get(osvBucketName);
    this.vulnerabilityIngester = vulnerabilityIngester;
  }

  private Stream<String> listEcosystems() {
    var ecosystems = bucket.get("ecosystems.txt");
    var content = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(ecosystems.getContent())));

    return content.lines();
  }

  public Multi<IngestionReport> loadAll() {
    return Multi.createFrom()
        .items(listEcosystems())
        .onItem()
        .transformToUniAndMerge(this::load)
        .runSubscriptionOn(executor)
        .onCompletion()
        .invoke(() -> LOGGER.info("Completed load of all ecosystems"));
  }

  public Uni<IngestionReport> load(String ecosystem) {
    return Uni.createFrom().item(bucket.get(ecosystem + "/all.zip"))
        .emitOn(Infrastructure.getDefaultWorkerPool())
        .onItem()
        .transform(all -> {
          LOGGER.infof("Loading [%s]", ecosystem);
          return load(ecosystem, new ByteArrayInputStream(all.getContent()));
        })
        .onFailure().retry().withBackOff(Duration.ofSeconds(2)).atMost(5)
        .onFailure().recoverWithItem(e -> {
          LOGGER.error("Failed to load vulnerabilities for: " + ecosystem, e);
          return new IngestionReport(ecosystem, 0, Collections.emptyList());
        })
        .onItem()
        .transform(report -> {
          List<String> missing = new ArrayList<>();
          for (var item : report.withoutSeverity()) {
            if (!vulnerabilityIngester.reconcile(item)) {
              missing.add(item);
            }
          }
          return new IngestionReport(report.name(), report.total(), missing);
        }).onItem()
        .invoke(report -> LOGGER.infof("Completed [%s] / Total vulnerabilities [%s] / Without severity [%s]",
            report.name(), report.total(), report.withoutSeverity().size()));
  }

  private IngestionReport load(String ecosystem, ByteArrayInputStream allFile) {
    var count = 0;
    List<String> incomplete = new ArrayList<>();
    try (var zis = new ZipInputStream(allFile)) {
      ZipEntry entry;
      while ((entry = zis.getNextEntry()) != null) {
        if (!entry.isDirectory() && entry.getName().endsWith(".json")) {
          var content = readZipEntryContent(zis);
          count++;
          var incompleteVuln = vulnerabilityIngester.save(entry.getName(), content);
          if (incompleteVuln != null) {
            incomplete.add(incompleteVuln);
          }
        }
      }
      zis.closeEntry();
    } catch (IOException e) {
      LOGGER.error("Unable to process Zip file: " + ecosystem, e);
    }
    return new IngestionReport(ecosystem, count, incomplete);
  }

  // Utility method to read the content of a ZipEntry
  private byte[] readZipEntryContent(InputStream zipInputStream) throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    byte[] buffer = new byte[1024];
    int length;
    while ((length = zipInputStream.read(buffer)) > 0) {
      byteArrayOutputStream.write(buffer, 0, length);
    }
    return byteArrayOutputStream.toByteArray();
  }

}
