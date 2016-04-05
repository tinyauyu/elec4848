int current;  //in mA

void setup() {
  Serial.begin(9600);

}

void loop() {
  current = analogRead(0)*(5.0/1023.0) * 1000;
  Serial.println(current);
  delay(100);
}
